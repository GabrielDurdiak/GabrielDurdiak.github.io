---
layout: post
title: Exploit Development y Analisis de CVE-2021-31956 NTFS Windows Kernel Pool Overflow
---

La vulnerabilidad se encuentra en el componente ntfs.sys dentro de la funcion NtfsQueryEaUserEaList, podemos ver el codigo vulnerable y el parche.

Funcion Vulnerable:

```c
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
          ea_block_size = ea_block->EaNameLength + ea_block->EaValueLength + 9;           // Attacker controlled from Ea
          if ( ea_block_size <= out_buf_length - padding )                                //  esta verficacio es donde puede desbordarse
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

## Seccion 1 
blablabal


### Subseccion 1 

sadasdasda
