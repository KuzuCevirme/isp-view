"""Build dist/ISPView.exe (single file, asks for admin rights on start).

    pip install -r requirements.txt pyinstaller
    python build.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ICON = os.path.join(HERE, "assets", "icon.ico")


def make_icon():
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((8, 56, 248, 200), fill=(30, 120, 220, 255))
    d.ellipse((80, 72, 176, 184), fill=(255, 255, 255, 255))
    d.ellipse((104, 96, 152, 160), fill=(20, 20, 30, 255))
    img.save(ICON, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


def main():
    os.makedirs(os.path.dirname(ICON), exist_ok=True)
    make_icon()
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--uac-admin", "--name", "ISPView", "--icon", ICON,
        "--add-data", f"{os.path.join(HERE, 'web')}{os.pathsep}web",
        os.path.join(HERE, "ispview.py"),
    ], cwd=HERE)
    print("Built", os.path.join(HERE, "dist", "ISPView.exe"))


if __name__ == "__main__":
    main()
