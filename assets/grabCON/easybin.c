undefined8 main(void)

{
  char local_38 [48];
  
  gets(local_38);
  printf("well lets check if you can bypass me!!!");
  return 0;
}

undefined8 vuln(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return 0;
}