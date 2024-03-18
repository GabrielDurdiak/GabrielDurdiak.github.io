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



