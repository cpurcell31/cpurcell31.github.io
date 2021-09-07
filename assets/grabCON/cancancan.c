undefined4 main(void)

{
  init((EVP_PKEY_CTX *)&stack0x00000004);
  puts("can you bypass me???");
  vuln();
  return 0;
}


void vuln(void)

{
  int in_GS_OFFSET;
  char *__buf;
  undefined4 uVar1;
  undefined4 uVar2;
  int local_78;
  char local_74 [100];
  int local_10;
  
  uVar2 = 0x80492d6;
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  for (local_78 = 0; local_78 < 2; local_78 = local_78 + 1) {
    uVar1 = 0x200;
    __buf = local_74;
    read(0,__buf,0x200);
    printf(local_74,__buf,uVar1,uVar2);
  }
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}


void win(void)

{
  system("/bin/sh");
  return;
}