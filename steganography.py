# from PIL import Image

# END_MARKER = '1111111111111110'

# def text_to_bits(text):
#     bits = ''.join(format(ord(c), '08b') for c in text)
#     return bits + END_MARKER

# def bits_to_text(bits):
#     end_index = bits.find(END_MARKER)
    
#     if end_index != -1:
#         bits = bits[:end_index]
    
#     chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
#     text = ""
    
#     for c in chars:
#         if len(c) < 8:
#             continue
#         text += chr(int(c, 2))
    
#     return text

# def embed(image_path, data, output_path):
#     image = Image.open(image_path)
#     pixels = list(image.getdata())

#     bits = text_to_bits(data)
#     new_pixels = []

#     bit_index = 0

#     for pixel in pixels:
#         if bit_index < len(bits):
#             r, g, b = pixel[:3]

#             r = (r & ~1) | int(bits[bit_index])
#             bit_index += 1

#             if bit_index < len(bits):
#                 g = (g & ~1) | int(bits[bit_index])
#                 bit_index += 1

#             if bit_index < len(bits):
#                 b = (b & ~1) | int(bits[bit_index])
#                 bit_index += 1

#             new_pixels.append((r, g, b))
#         else:
#             new_pixels.append(pixel)

#     image.putdata(new_pixels)
#     image.save(output_path)

# def extract(image_path):
#     image = Image.open(image_path)
#     pixels = list(image.getdata())

#     bits = ""

#     for pixel in pixels:
#         r, g, b = pixel[:3]

#         bits += str(r & 1)
#         bits += str(g & 1)
#         bits += str(b & 1)

#     return bits_to_text(bits)


from PIL import Image

END_MARKER = '1111111111111110'

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text) + END_MARKER

def bits_to_text(bits):
    end = bits.find(END_MARKER)
    bits = bits[:end] if end != -1 else bits
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)

def embed(image_path, data, output_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())

    bits = text_to_bits(data)
    if len(bits) > len(pixels) * 3:
        raise ValueError("Data too large")

    new_pixels = []
    index = 0

    for pixel in pixels:
        r, g, b = pixel[:3]

        if index < len(bits):
            r = (r & ~1) | int(bits[index])
            index += 1
        if index < len(bits):
            g = (g & ~1) | int(bits[index])
            index += 1
        if index < len(bits):
            b = (b & ~1) | int(bits[index])
            index += 1

        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    image.save(output_path)

def extract(image_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())

    bits = ''.join(str(channel & 1) for pixel in pixels for channel in pixel[:3])
    return bits_to_text(bits)


def analyze_image(image_path):
    """
    Returns True if the image likely contains hidden text data.

    Old bug: searched for END_MARKER anywhere in the bit stream.
    The 17-bit pattern '1111111111111110' occurs ~5.7 times on average in
    750 000 random bits, so the old version returned True for virtually
    every clean image (100 % false-positive rate).

    Fix: the marker is only meaningful when
      1. it starts at a bit position that is a multiple of 8 (byte-aligned),
         because embed() writes one ASCII character per 8 bits, and
      2. the bits that precede it decode to a non-empty string that matches
         the base64 pattern used by aes.encrypt() (at least 44 chars).
    Both conditions together make an accidental match astronomically unlikely.
    """
    import re
    from PIL import Image

    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())
    bits = ''.join(str(ch & 1) for px in pixels for ch in px[:3])

    pos = 0
    while True:
        pos = bits.find(END_MARKER, pos)
        if pos == -1:
            return False                          # marker never found

        if pos % 8 == 0 and pos > 0:             # must be byte-aligned
            data_bits = bits[:pos]
            if len(data_bits) % 8 == 0:
                chars = ''.join(
                    chr(int(data_bits[i:i+8], 2))
                    for i in range(0, len(data_bits), 8)
                )
                # AES-EAX output in base64 is always ≥ 44 chars and
                # contains only base64-alphabet characters
                if len(chars) >= 44 and re.fullmatch(r'[A-Za-z0-9+/]+=*', chars):
                    return True

        pos += 1                                  # try next occurrence

IMAGE_HEADER = 'IMG:'
IMAGE_END_MARKER = '1111111111111110'

def _image_to_bits(secret_path):
    from PIL import Image

    secret = Image.open(secret_path).convert("RGB")

    max_pixels = 50000
    current_pixels = secret.size[0] * secret.size[1]

    if current_pixels > max_pixels:
        scale = (max_pixels / current_pixels) ** 0.5
        new_size = (int(secret.size[0] * scale), int(secret.size[1] * scale))
        secret = secret.resize(new_size, Image.BICUBIC)

    w, h = secret.size

    header = IMAGE_HEADER + f"{w},{h},"
    header_bits = ''.join(format(ord(c), '08b') for c in header)

    pixel_bits = ''.join(
        format(channel, '08b')
        for pixel in secret.getdata()
        for channel in pixel[:3]
    )

    return header_bits + pixel_bits + IMAGE_END_MARKER

def _bits_to_image(bits):
    from PIL import Image

    end = bits.find(IMAGE_END_MARKER)
    bits = bits[:end] if end != -1 else bits

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    text = ''.join(chars)

    if not text.startswith(IMAGE_HEADER):
        raise ValueError("No hidden image found.")

    header_end = text.find(',', len(IMAGE_HEADER))
    header_end2 = text.find(',', header_end + 1)

    w = int(text[len(IMAGE_HEADER):header_end])
    h = int(text[header_end + 1:header_end2])

    pixel_bits = bits[(header_end2 + 1) * 8:]

    pixels = []
    total_pixels = w * h

    for i in range(total_pixels):
        offset = i * 24
        if offset + 24 > len(pixel_bits):
            pixels.append((0, 0, 0))
            continue

        r = int(pixel_bits[offset:offset+8], 2)
        g = int(pixel_bits[offset+8:offset+16], 2)
        b = int(pixel_bits[offset+16:offset+24], 2)
        pixels.append((r, g, b))

    img = Image.new("RGB", (w, h))
    img.putdata(pixels)
    return img

def embed_image(cover_path, secret_path, output_path):
    from PIL import Image
    cover = Image.open(cover_path).convert("RGB")
    cover_pixels = list(cover.getdata())

    bits = _image_to_bits(secret_path)

    if len(bits) > len(cover_pixels) * 3:
        raise ValueError("Secret image too large")

    new_pixels = []
    index = 0

    for pixel in cover_pixels:
        r, g, b = pixel

        if index < len(bits):
            r = (r & ~1) | int(bits[index]); index += 1
        if index < len(bits):
            g = (g & ~1) | int(bits[index]); index += 1
        if index < len(bits):
            b = (b & ~1) | int(bits[index]); index += 1

        new_pixels.append((r, g, b))

    cover.putdata(new_pixels)
    cover.save(output_path)

def extract_image(stego_path):
    from PIL import Image
    image = Image.open(stego_path).convert("RGB")
    pixels = list(image.getdata())

    bits = ''.join(str(channel & 1) for pixel in pixels for channel in pixel[:3])
    return _bits_to_image(bits)