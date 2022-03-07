from PIL import Image


filename = 'bluer.png'
img = Image.open(filename)
pixels = img.getdata()
pix_list = list(pixels)
width, height = img.size


difs_by_row = list()
for y in range(height):
    difference = 0
    for x in range(width):
        pixel = list(img.getpixel((x,y)))
        difference += pixel[0] - 34
        difference += pixel[1] - 86
        difference += pixel[2] - 166
    difs_by_row.append(difference)


result = ""
for dif in difs_by_row:
    if dif != 0:
        result += chr(dif)

print(result)
