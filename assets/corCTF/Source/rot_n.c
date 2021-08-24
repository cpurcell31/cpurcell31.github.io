char rot_n(char param_1,int param_2)

{
  char *pcVar1;
  
  pcVar1 = strchr(ASCII_UPPER,(int)param_1);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = strchr(ASCII_LOWER,(int)param_1);
    if (pcVar1 != (char *)0x0) {
      param_1 = ASCII_LOWER[(param_1 + -0x61 + param_2) % 0x1a];
    }
  }
  else {
    param_1 = ASCII_UPPER[(param_1 + -0x41 + param_2) % 0x1a];
  }
  return param_1;
}