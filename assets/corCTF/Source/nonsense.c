
undefined8 main(void)

{
  char cVar1;
  int iVar2;
  size_t sVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  int local_100;
  int local_fc;
  undefined8 local_f0;
  char local_e8 [64];
  char local_a8 [27];
  undefined auStack141 [37];
  char local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_e8,0x40,stdin);
  sVar3 = strcspn(local_e8,"\n");
  local_e8[sVar3] = '\0';
  sVar3 = strlen(local_e8);
  local_f0 = 7;
  iVar2 = strncmp("corctf{",local_e8,7);
  
  //is inp = "corctf{*" and is inp[len-1] = '}' and is len(inp) = 28?
  if (((iVar2 == 0) && (local_e8[sVar3 - 1] == '}')) && (sVar3 == 0x1c)) {
  
    //copy 20 bytes of inp+7 into local_a8
    memcpy(local_a8,local_e8 + local_f0,0x1b - local_f0);
    auStack141[-local_f0] = 0;
    
    //index = 0
    local_100 = 0;
    
    //search for prime number
    while( true ) {
      sVar3 = strlen(local_a8);
      if (sVar3 <= (ulong)(long)local_100) break;
      local_fc = local_100 << 2;
      while( true ) {
        cVar1 = is_prime(local_fc);
        if (cVar1 == '\x01') break;
        local_fc = local_fc + 1;
      }
      
      //call rot_n with input of some character, some_prime
      cVar1 = rot_n((int)local_a8[local_100],local_fc);
      //Set local_68[index] to the result
      local_68[local_100] = cVar1;
      //Increment index
      local_100 = local_100 + 1;
    }
    
    sVar3 = strlen(local_68);
    local_68[sVar3 + 1] = '\0';
    
    //encrypt 20 bytes of check by xoring each byte with 42
    memfrob(check,0x14);
    iVar2 = strcmp(local_68,check);
    
    //if check = local_68 then print correct!
    if (iVar2 == 0) {
      puts("correct!");
      uVar4 = 0;
    }
    
    //else print rev is hard i guess...
    else {
      puts("rev is hard i guess...");
      uVar4 = 1;
    }
  }
  else {
    puts("rev is hard i guess...");
    uVar4 = 1;
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar4;
}

