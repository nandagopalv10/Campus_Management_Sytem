import random
import time
from PIL import Image, ImageDraw, ImageFont

def generate_numeric_captcha(length=4):
    captcha_characters = string.digits
    captcha_text = ''.join(random.choices(captcha_characters, k=length))
    return captcha_text

def create_numeric_image(text):
    image_width = 120
    image_height = 60
    font_size = 40

    background_color = (255, 255, 255)
    text_color = (0, 0, 0)

    font = ImageFont.load_default()  # Load the default system font
    image = Image.new("RGB", (image_width, image_height), background_color)
    draw = ImageDraw.Draw(image)

    x_offset = 10
    for char in text:
        y_offset = random.randint(-5, 5)
        draw.text((x_offset, 10 + y_offset), char, fill=text_color, font=font)
        x_offset += font.getsize(char)[0] + random.randint(2, 5)

    return image

def main():
    captcha_text = generate_numeric_captcha()
    distorted_image = create_numeric_image(captcha_text)
    distorted_image.show()

    start_time = time.time()
    user_input = input("Enter the CAPTCHA: ")
    end_time = time.time()

    if user_input == captcha_text:
        if end_time - start_time <= 15:
            print("CAPTCHA passed within time limit!")
        else:
            print("CAPTCHA passed, but time limit exceeded.")
    else:
        print("CAPTCHA failed.")

if __name__ == "__main__":
    main()
