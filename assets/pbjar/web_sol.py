import requests, time

url = 'http://147.182.172.217:42100/v{}'


def query(s):
  ret = None
  while ret is None:
    time.sleep(0.5)
    in_url = url.format(s)
    res = requests.get(in_url).text
    if 'version not found' in res: ret = False
    else: ret = True
    print(ret)
  return ret

def binsearch(lo, hi):
    while lo < hi:
        mid = (hi+lo) // 2
        if query(mid):  
            lo = mid+1
        else:
            hi = mid
    return lo

def solve():
    print("Beginning Binary Search...")
    val = binsearch(3, 300000000000)
    print(val)

solve()

