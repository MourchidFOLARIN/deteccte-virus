from PIL import Image, ImageDraw

taille = 300
img = Image.new("RGBA", (taille, taille), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

vert = (61, 214, 140, 255)
vert_fonce = (30, 110, 70, 255)
blanc = (255, 255, 255, 255)

points_bouclier = [
    (150, 15),
    (270, 55),
    (270, 150),
    (150, 290),
    (30, 150),
    (30, 55),
]
draw.polygon(points_bouclier, fill=vert, outline=vert_fonce, width=6)

points_coche = [
    (95, 150),
    (135, 195),
    (210, 100),
    (195, 85),
    (133, 160),
    (108, 133),
]
draw.polygon(points_coche, fill=blanc)

img.save("logo.png")
print("Logo généré : logo.png")
