from PIL import Image, ImageDraw
import os

def create_simple_icon(size):
    """Create a simple colored square icon"""
    img = Image.new('RGBA', (size, size), (67, 97, 238, 255)) 
    draw = ImageDraw.Draw(img)
    
  
    draw.rectangle([size//4, size//4, 3*size//4, 3*size//4], 
                   outline=(255, 255, 255), width=size//16)
    

    if size >= 48:
        draw.line([(size//3, 2*size//3), (size//2, 3*size//4)], 
                  fill=(255, 255, 255), width=size//12)
        draw.line([(size//2, 3*size//4), (2*size//3, size//3)], 
                  fill=(255, 255, 255), width=size//12)
    
    return img


os.makedirs('icons', exist_ok=True)


sizes = [16, 48, 128]
for size in sizes:
    icon = create_simple_icon(size)
    icon.save(f'icons/shield{size}.png')
    print(f"✓ Created icons/shield{size}.png ({size}x{size})")

print("\n✅ All icons created successfully!")
print("Now reload the extension in Chrome.")