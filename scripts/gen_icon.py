#!/usr/bin/env python3
"""生成应用图标：蓝紫渐变圆角底 + 白色虚线循环环 + 节点 + 白色盾牌 + dynv6 / DDNS 字样。

优先使用 Pillow（可绘制渐变与平滑文字）；没有 Pillow 时回退到纯标准库的简化版。
生成的 PNG 会作为项目资产保存，构建脚本默认不覆盖。
"""
import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIZES = [16, 24, 32, 48, 64, 128, 256]
W = 256


def outputs():
    d = os.path.join(ROOT, "app", "ui", "images")
    os.makedirs(d, exist_ok=True)
    files = [(os.path.join(d, "ICON_%d.PNG" % s), s) for s in SIZES]
    files += [(os.path.join(ROOT, "ICON.PNG"), 64), (os.path.join(ROOT, "ICON_256.PNG"), 256)]
    return files


def font_path():
    for p in (
        r"C:\Windows\Fonts\segoeuib.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        if os.path.exists(p):
            return p
    return None


def with_pillow():
    from PIL import Image, ImageDraw, ImageFont

    S = 1024
    k = S / W
    u = lambda v: int(round(v * k))

    # 蓝紫对角渐变
    c0, c1 = (76, 125, 247), (155, 93, 229)
    grad = Image.new("RGBA", (S, S))
    gp = grad.load()
    for y in range(S):
        for x in range(S):
            t = (x + y) / (2 * S - 2)
            gp[x, y] = (
                int(c0[0] + (c1[0] - c0[0]) * t),
                int(c0[1] + (c1[1] - c0[1]) * t),
                int(c0[2] + (c1[2] - c0[2]) * t),
                255,
            )
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, S - 1, S - 1), radius=u(56), fill=255)
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    ink = (59, 79, 216, 255)

    # 白色虚线循环环
    cx, cy, r = u(128), u(116), u(78)
    box = (cx - r, cy - r, cx + r, cy + r)
    for a in range(0, 360, 15):
        d.arc(box, a, a + 9, fill=white, width=u(2.4))

    # 环上节点：白色实心圆，其中三处改为箭头
    def pt(deg):
        rad = math.radians(deg)
        return cx + r * math.cos(rad), cy - r * math.sin(rad)

    arrow_angles = {45, 165, 285}
    for deg in range(0, 360, 45):
        x, y = pt(deg)
        if deg in arrow_angles:
            rad = math.radians(deg)
            tx, ty = -math.sin(rad), -math.cos(rad)
            nx, ny = -ty, tx
            size = u(9)
            tip = (x + tx * size, y + ty * size)
            b1 = (x - tx * size * 0.6 + nx * size * 0.7, y - ty * size * 0.6 + ny * size * 0.7)
            b2 = (x - tx * size * 0.6 - nx * size * 0.7, y - ty * size * 0.6 - ny * size * 0.7)
            d.polygon([tip, b1, b2], fill=white)
        else:
            rr = u(7)
            d.ellipse((x - rr, y - rr, x + rr, y + rr), fill=white)

    # 中央白色盾牌：圆角上半 + 尖底
    d.rounded_rectangle((u(90), u(88), u(166), u(148)), radius=u(14), fill=white)
    d.polygon([(u(90), u(132)), (u(166), u(132)), (u(128), u(170))], fill=white)

    fp = font_path()
    def face(size):
        return ImageFont.truetype(fp, u(size)) if fp else ImageFont.load_default()

    d.text((u(128), u(118)), "dynv6", font=face(23), fill=ink, anchor="mm")
    d.text((u(128), u(214)), "DDNS", font=face(20), fill=white, anchor="mm")

    master = img.resize((W, W), Image.LANCZOS)
    for path, s in outputs():
        (master if s == W else master.resize((s, s), Image.LANCZOS)).save(path, "PNG")
    return True


def fallback():
    """无 Pillow 时的纯标准库简化版：浅蓝底 + 蓝盾 + 白锁。"""
    buf = [[(0, 0, 0, 0) for _ in range(W)] for _ in range(W)]

    def px(x, y, c):
        x, y = int(round(x)), int(round(y))
        if 0 <= x < W and 0 <= y < W:
            buf[y][x] = (c[0], c[1], c[2], 255)

    def disc(cx, cy, r, c):
        for y in range(int(cy - r - 1), int(cy + r + 2)):
            for x in range(int(cx - r - 1), int(cx + r + 2)):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                    px(x, y, c)

    def rounded(x0, y0, x1, y1, rad, c):
        for y in range(y0, y1):
            for x in range(x0, x1):
                dx = max(x0 + rad - x, 0, x - (x1 - 1 - rad))
                dy = max(y0 + rad - y, 0, y - (y1 - 1 - rad))
                if dx * dx + dy * dy <= rad * rad:
                    px(x, y, c)

    BG, BLUE, WHITE = (234, 243, 255), (37, 99, 235), (255, 255, 255)
    rounded(4, 4, 252, 252, 56, BG)
    for y in range(58, 188):
        t = (y - 58) / 130.0
        half = 55 - 3 * t if t < 0.55 else 55 * (1 - ((t - 0.55) / 0.45) ** 1.3)
        for x in range(68, 188):
            if abs(x - 128) <= half:
                px(x, y, BLUE)
    for i in range(181):
        a = math.radians(i)
        disc(128 + 20 * math.cos(a), 118 - 20 * math.sin(a), 5, WHITE)
    rounded(100, 114, 156, 158, 12, WHITE)
    disc(128, 134, 6, BLUE)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    for path, s in outputs():
        rows = []
        for ty in range(s):
            y0, y1 = ty * W // s, max(ty * W // s + 1, (ty + 1) * W // s)
            line = bytearray()
            for tx in range(s):
                x0, x1 = tx * W // s, max(tx * W // s + 1, (tx + 1) * W // s)
                rr = gg = bb = aa = n = 0
                for yy in range(y0, y1):
                    for xx in range(x0, x1):
                        pr, pg, pb, pa = buf[yy][xx]
                        rr += pr * pa
                        gg += pg * pa
                        bb += pb * pa
                        aa += pa
                        n += 1
                line += bytes((0, 0, 0, 0) if aa == 0 else (rr // aa, gg // aa, bb // aa, aa // n))
            rows.append(b"\x00" + bytes(line))
        ihdr = struct.pack(">IIBBBBB", s, s, 8, 6, 0, 0, 0)
        png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
        open(path, "wb").write(png)
    return False


def write_ico():
    """从 256px 图标生成 Windows .ico，并同步到 src/assets 供 go:embed 使用。"""
    try:
        from PIL import Image
    except Exception:
        return
    src = os.path.join(ROOT, "ICON_256.PNG")
    if not os.path.exists(src):
        return
    import shutil
    im = Image.open(src).convert("RGBA")
    os.makedirs(os.path.join(ROOT, "assets"), exist_ok=True)
    ico = os.path.join(ROOT, "assets", "dynv6.ico")
    im.save(ico, format="ICO", sizes=[(s, s) for s in SIZES])
    os.makedirs(os.path.join(ROOT, "src", "assets"), exist_ok=True)
    shutil.copy(ico, os.path.join(ROOT, "src", "assets", "dynv6.ico"))
    print("Windows 图标已生成:", ico)


def main():
    master_path = os.path.join(ROOT, "assets", "icon_master.png")
    if os.path.exists(master_path):
        try:
            from PIL import Image
            master = Image.open(master_path).convert("RGBA")
            for path, s in outputs():
                master.resize((s, s), Image.LANCZOS).save(path, "PNG")
            print("图标已由母版生成:", master_path, ", ".join(str(s) for s in SIZES))
            write_ico()
            return
        except Exception as e:
            print("母版读取失败，回退到程序绘制:", e)
    try:
        ok = with_pillow()
    except Exception as e:
        print("Pillow 绘制失败，改用简化版:", e)
        ok = fallback()
    write_ico()
    print("图标已生成（%s）：" % ("Pillow 高质量版" if ok else "标准库简化版"), ", ".join(str(s) for s in SIZES))


if __name__ == "__main__":
    main()
