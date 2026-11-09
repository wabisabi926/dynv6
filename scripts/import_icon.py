#!/usr/bin/env python3
"""把「飞牛原生应用图标设计.png」去水印、圆角透明化后导入为项目图标母版。

用法：
  python scripts/import_icon.py                       # 使用默认源图
  python scripts/import_icon.py --source <图片路径>   # 指定源图
  python scripts/import_icon.py --box 1600,1880,2030,2025  # 自定义水印区域

母版保存到 assets/icon_master.png；之后 gen_icon.py 会优先由母版生成各尺寸图标。
"""
import argparse
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SOURCE = os.path.join(os.path.dirname(ROOT), "飞牛原生应用图标设计.png")
OUT = os.path.join(ROOT, "assets", "icon_master.png")
DEFAULT_BOX = (1600, 1880, 2030, 2025)


def clamp(v):
    return max(0, min(255, int(round(v))))


def inpaint_watermark(im, box):
    """按每列上方的蓝紫渐变线性外推，重建水印区域（不引入接缝）。"""
    px = im.load()
    x0, y0, x1, y1 = box
    w, h = im.size
    x1, y1 = min(x1, w), min(y1, h)
    for x in range(x0, x1):
        def avg(a, b):
            vals = [px[x, y] for y in range(a, b)]
            n = len(vals)
            return tuple(sum(v[i] for v in vals) / n for i in range(3))

        c_start = avg(max(0, y0 - 140), max(1, y0 - 120))
        c_end = avg(max(0, y0 - 30), max(1, y0 - 10))
        span = 90.0
        slope = tuple((c_end[i] - c_start[i]) / span for i in range(3))
        base_y = y0 - 20
        for y in range(y0, y1):
            dy = y - base_y
            px[x, y] = tuple(clamp(c_end[i] + slope[i] * dy) for i in range(3))
    return im


def rounded_alpha(size, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=DEFAULT_SOURCE)
    ap.add_argument("--box", default=",".join(str(v) for v in DEFAULT_BOX))
    ap.add_argument("--radius", type=int, default=340)
    ap.add_argument("--master-size", type=int, default=512)
    args = ap.parse_args()

    box = tuple(int(v) for v in args.box.split(","))
    im = Image.open(args.source).convert("RGB")
    print("源图:", args.source, im.size, "水印区域:", box)
    im = inpaint_watermark(im, box)
    master = im.convert("RGBA")
    master.putalpha(rounded_alpha(im.width, args.radius))
    master = master.resize((args.master_size, args.master_size), Image.LANCZOS)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    master.save(OUT, "PNG")
    print("母版已生成:", OUT, master.size, os.path.getsize(OUT), "字节")


if __name__ == "__main__":
    main()
