"""Native Linux compatibility probe. Writes only metadata and synthetic-image statistics."""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import subprocess

import numpy as np
from scipy.ndimage import minimum_filter


EXPECTED_SHA256 = "37e290dbd0053f00e508d02a6b3a2a990432dad1eb74c40a52ca899f0f225ecc"


def sample_metadata(path):
    if path.stat().st_size != 92_675 or hashlib.sha256(path.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Probe accepts only the verified Kodak DC50 sample")
    library = ctypes.CDLL(ctypes.util.find_library("raw"))
    context_type = ctypes.c_void_p
    library.libraw_init.argtypes = [ctypes.c_uint]
    library.libraw_init.restype = context_type
    library.libraw_open_file.argtypes = [context_type, ctypes.c_char_p]
    library.libraw_unpack.argtypes = [context_type]
    library.libraw_close.argtypes = [context_type]
    library.libraw_close.restype = None
    context = library.libraw_init(0)
    if not context:
        raise RuntimeError("libraw_init failed")
    try:
        opened = library.libraw_open_file(context, os.fsencode(path))
        if opened:
            raise RuntimeError(f"libraw_open_file returned {opened}")
        dimensions = []
        for name in ("raw_width", "raw_height", "iwidth", "iheight"):
            fn = getattr(library, "libraw_get_" + name)
            fn.argtypes = [context_type]
            fn.restype = ctypes.c_int
            dimensions.append(fn(context))
        if dimensions != [768, 512, 768, 512]:
            raise ValueError(f"Unexpected dimensions {dimensions}")
        unpacked = library.libraw_unpack(context)
        if unpacked:
            raise RuntimeError(f"libraw_unpack returned {unpacked}")
    finally:
        library.libraw_close(context)
    metadata = subprocess.check_output([
        "magick", "-limit", "memory", "96MiB", "-limit", "map", "128MiB",
        "-limit", "disk", "0", "-limit", "width", "3000", "-limit", "height", "3000",
        str(path), "-format", "%m %wx%h %[colorspace] %[depth]", "info:",
    ], text=True, timeout=8)
    return {"provider": "rawsamples.ch via letmaik/rawpy", "license": "CC BY-NC-SA 4.0",
            "source_sha256": EXPECTED_SHA256, "bytes": path.stat().st_size,
            "libraw_open_status": opened, "libraw_unpack_status": unpacked,
            "sensor_dimensions": dimensions[:2], "image_dimensions": dimensions[2:],
            "decoded_image_metadata": metadata}


def check_dehaze():
    # The clear scene gives an independent exact reference. Different colors have a zero channel.
    y, x = np.indices((96, 128))
    palette = np.array([[0., .35, .8], [.2, .5, 0.], [.85, 0., .65]])
    clear = palette[(x // 8 + y // 8) % 3]
    air = np.array([.86, .93, 1.])
    hazy = clear * .6 + air * .4
    hazy[:24, :] = air
    dark = minimum_filter(hazy.min(axis=2), size=15, mode="nearest").ravel()
    samples = max(1, dark.size // 1000)
    bright = np.argpartition(dark, -samples)[-samples:]
    pixels = hazy.reshape(-1, 3)
    estimated_air = pixels[bright[pixels[bright].sum(axis=1).argmax()]]
    normalized_dark = minimum_filter((hazy / estimated_air).min(axis=2), size=15, mode="nearest")
    transmission = np.maximum(.1, 1. - .95 * normalized_dark)
    estimated = np.clip((hazy - estimated_air) / transmission[:, :, None] + estimated_air, 0, 1)
    # Omit the constructed sky and the filter's boundary with that sky.
    reference = clear[32:]
    before = np.abs(reference - hazy[32:]).mean()
    after = np.abs(reference - estimated[32:]).mean()
    if not (0 < after < before and np.allclose(estimated_air, air)):
        raise AssertionError("Synthetic recovery failed")
    return {"input": "generated 128x96 linear RGB scene", "atmospheric_light": estimated_air.tolist(),
            "window": 15, "omega": .95, "minimum_transmission": .10,
            "hazy_mean_absolute_error": float(before), "recovered_mean_absolute_error": float(after),
            "evaluated_pixels": reference.shape[0] * reference.shape[1]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pinned_kdc", type=Path)
    args = parser.parse_args()
    packages = subprocess.check_output(
        ["dpkg-query", "-W", "libraw23t64", "imagemagick", "python3-scipy", "python3-numpy"],
        text=True,
    ).splitlines()
    print(json.dumps({"packages": packages, "native_camera_decode": sample_metadata(args.pinned_kdc),
                      "synthetic_dehaze": check_dehaze()}, indent=2))
