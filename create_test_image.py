"""Create a simple test image for testing the library."""

from PIL import Image, ImageDraw
from pathlib import Path

# Create a simple test image
img = Image.new('RGB', (800, 600), color='white')
draw = ImageDraw.Draw(img)

# Draw some content
draw.rectangle([100, 100, 700, 500], outline='black', width=3, fill='lightblue')
draw.text((300, 250), "Test Image", fill='black')

# Save as JPEG and PNG
output_dir = Path(__file__).parent / "test_images"
output_dir.mkdir(exist_ok=True)

jpg_path = output_dir / "test_photo.jpg"
png_path = output_dir / "test_photo.png"

img.save(jpg_path, 'JPEG', quality=95)
img.save(png_path, 'PNG')

print(f"✓ Test images created:")
print(f"  - {jpg_path}")
print(f"  - {png_path}")
