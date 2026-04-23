# CTF Forensics - Steganography

## Table of Contents
- [Quick Tools](#quick-tools)
- [Binary Border Steganography](#binary-border-steganography)
- [JPEG Thumbnail Pixel-to-Text Mapping (RuCTF 2013)](#jpeg-thumbnail-pixel-to-text-mapping-ructf-2013)
- [Conditional LSB Extraction — Near-Black Pixel Filter (BaltCTF 2013)](#conditional-lsb-extraction--near-black-pixel-filter-baltctf-2013)
- [GIF Frame Differential + Morse Code (BaltCTF 2013)](#gif-frame-differential--morse-code-baltctf-2013)
- [GZSteg + Spammimic Text Steganography (VolgaCTF 2013)](#gzsteg--spammimic-text-steganography-volgactf-2013)

For 2024-2026 era techniques (PDF, PNG chunks, JPEG quantization, F5, jigsaw, QR tiles), see [steganography-2.md](steganography-2.md).

---

## Quick Tools

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP analysis
stegsolve                    # Visual analysis

# Steghide brute-force (0xFun 2026)
stegseek image.jpg rockyou.txt  # Faster than stegcracker
# Common weak passphrases: "simple", "password", "123456"
```

---

## Binary Border Steganography

**Pattern (Framer, PascalCTF 2026):** Message encoded as black/white pixels in 1-pixel border around image.

```python
from PIL import Image

img = Image.open('output.jpg')
w, h = img.size
bits = []

# Read border clockwise: top → right → bottom (reversed) → left (reversed)
for x in range(w): bits.append(0 if sum(img.getpixel((x, 0))[:3]) < 384 else 1)
for y in range(1, h): bits.append(0 if sum(img.getpixel((w-1, y))[:3]) < 384 else 1)
for x in range(w-2, -1, -1): bits.append(0 if sum(img.getpixel((x, h-1))[:3]) < 384 else 1)
for y in range(h-2, 0, -1): bits.append(0 if sum(img.getpixel((0, y))[:3]) < 384 else 1)

# Convert bits to ASCII
msg = ''.join(chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits)-7, 8))
```

---

## JPEG Thumbnail Pixel-to-Text Mapping (RuCTF 2013)

**Pattern:** JPEG contains an embedded thumbnail where dark pixels map 1:1 to character positions in visible text on the main image.

```python
from PIL import Image
# Extract thumbnail: exiftool -b -ThumbnailImage secret.jpg > thumb.jpg
thumb = Image.open('thumb.jpg')
text_lines = ["line1 of visible text...", "line2..."]  # OCR or type from photo
result = ''
for y in range(thumb.height):
    for x in range(thumb.width):
        r, g, b = thumb.getpixel((x, y))[:3]
        if r < 100 and g < 100 and b < 100:  # Dark pixel = selected char
            result += text_lines[y][x]
```

**Key insight:** Extract thumbnails with `exiftool -b -ThumbnailImage`. Dark pixels act as a selection mask over the photographed text. Use OCR (ABBYY FineReader, Tesseract) to get the text grid, then map dark thumbnail pixels to character positions.

---

## Conditional LSB Extraction — Near-Black Pixel Filter (BaltCTF 2013)

**Pattern:** Only pixels with R<=1 AND G<=1 AND B<=1 carry steganographic data. Standard LSB tools miss the data because they process all pixels.

```python
from PIL import Image
img = Image.open('image.png')
bits = ''
for pixel in img.getdata():
    r, g, b = pixel[0], pixel[1], pixel[2]
    if not (r <= 1 and g <= 1 and b <= 1):
        continue  # Skip non-carrier pixels
    bits += str(r & 1) + str(g & 1) + str(b & 1)
# Convert bits to bytes
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
```

**Key insight:** When standard `zsteg`/`stegsolve` find nothing, try filtering pixels by value range before LSB extraction. The carrier pixels may be restricted to near-black, near-white, or specific color ranges.

---

## GIF Frame Differential + Morse Code (BaltCTF 2013)

**Pattern:** Animated GIF contains hidden dots visible only when comparing frames against originals. Dots encode Morse code.

```bash
# Extract frames from animated GIF
convert animated.gif frame_%03d.gif

# Compare each frame against its base using ImageMagick
for i in $(seq 1 100); do
    compare -fuzz 10% -compose src stego_$i.gif original_$i.gif diff_$i.gif
done

# Inspect diff images — dots appear at specific positions
# Map dot patterns to Morse: small dot = dit, large dot = dah
```

**Key insight:** `compare -fuzz 10%` reveals subtle single-pixel modifications invisible to the eye. The diff images show isolated dots whose timing/spacing encodes Morse code. Decode dots → dashes/dots → letters → flag.

---

## GZSteg + Spammimic Text Steganography (VolgaCTF 2013)

**Pattern:** Data hidden within gzip compression metadata, decoded through spammimic.com.

1. Apply GZSteg patches to gzip 1.2.4 source, compile, extract with `gzip --s` flag
2. Extracted text resembles spam email — submit to [spammimic.com](https://www.spammimic.com/) decoder
3. Decoded output is the flag

**Key insight:** GZSteg exploits redundancy in the gzip DEFLATE compression format to embed covert data. The extracted payload often uses a second steganographic layer (spammimic encodes data as innocuous-looking spam text). Look for `.gz` files larger than expected for their content.
