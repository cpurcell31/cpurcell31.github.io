import string

dic = string.printable
M, s, l, C = 7777771, [], 1337, [] 
n=[]

k = [list(map(int, list(' '.join(bin(ord(i))[2:]).split()))) for i in dic]

def num_gen(first, last):

   o = [[1]]                       
   cnt = 1                            
   while cnt <= last:
       if cnt >= first:
           yield o[-1][0]           
       row = [o[-1][-1]]            
       for b in o[-1]:
        row.append(row[-1] + b)  
       cnt += 1                       
       o.append(row)
           
for i in num_gen(7, 13):
       s.append(i)
              
for i in range(len(s)):
    ni = ((l*s[i]) % M)           
    n.append(ni)

j = dict()
for p in k:
    C_curr = []
    for (x,y) in zip(p, n):
        C_ = x*y
        C_curr.append(C_)
    C += [sum(C_curr)]


print(M, s, l, C)
print(n)

enc = [15051976, 12005794, 3916945, 6470614, 7771050, 19992202, 17519217, 19419005, 13883825, 18691766, 13988655, 6979140, 14478779, 13988655, 8943599, 13883825, 25527382, 6384186, 13988655, 16461640, 25527382, 16224525, 6707729, 21488294, 25527382, 14392351, 6707729, 16733051, 12005794, 25527382, 6470614, 3916945, 7771050, 12711276, 21673277]

print(len(enc))

for c in enc:
    if c in C:
        print(c)
