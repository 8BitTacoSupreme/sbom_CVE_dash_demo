#!/usr/bin/env python3
"""
Update Architecture Diagram with GitHub/GHSA Logo

Adds GitHub Security Advisory (GHSA) logo to the architecture diagram
between OSV and CISA on the left side.
"""

import io
import urllib.request
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Error: Pillow is required. Install with: pip install Pillow")
    exit(1)


def download_github_logo():
    """Download GitHub's official Invertocat mark."""
    url = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return Image.open(io.BytesIO(response.read()))
    except Exception as e:
        print(f"Could not download GitHub logo: {e}")
        return None


def create_github_text_logo(width=100, height=50):
    """Create a simple GitHub text logo as fallback."""
    img = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)

    # Try to use a bold font, fall back to default
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 24)
    except:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
        except:
            font = ImageFont.load_default()

    # Draw "GitHub" text in black
    text = "GitHub"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    draw.text((x, y), text, fill=(0, 0, 0, 255), font=font)

    return img


def create_ghsa_badge(width=120, height=60):
    """Create a styled GHSA badge similar to other logos in the diagram."""
    img = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)

    # Draw rounded rectangle background (GitHub's dark color)
    bg_color = (36, 41, 47, 255)  # GitHub's dark gray
    draw.rounded_rectangle([(0, 0), (width-1, height-1)], radius=8, fill=bg_color)

    # Try to get a good font
    try:
        font_large = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
        font_small = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 12)
    except:
        try:
            font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
            font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        except:
            font_large = ImageFont.load_default()
            font_small = ImageFont.load_default()

    # Draw GitHub icon (simple octocat silhouette approximation - a circle)
    icon_size = 24
    icon_x = 12
    icon_y = (height - icon_size) // 2
    draw.ellipse([(icon_x, icon_y), (icon_x + icon_size, icon_y + icon_size)],
                 fill=(255, 255, 255, 255))

    # Draw "GHSA" text
    text = "GHSA"
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_x = icon_x + icon_size + 10
    text_y = (height - (bbox[3] - bbox[1])) // 2 - 2
    draw.text((text_x, text_y), text, fill=(255, 255, 255, 255), font=font_large)

    return img


def add_github_to_diagram(input_path, output_path):
    """Add GitHub/GHSA logo to the architecture diagram."""
    # Load the original image
    original = Image.open(input_path)
    print(f"Original image size: {original.size}")

    # Create a copy to work with
    diagram = original.copy()
    if diagram.mode != 'RGBA':
        diagram = diagram.convert('RGBA')

    # Try to download the official GitHub logo first
    github_logo = download_github_logo()

    if github_logo:
        print("Using downloaded GitHub logo")
        # Resize to match other logos (~80px height, preserve aspect ratio)
        target_height = 70
        aspect = github_logo.width / github_logo.height
        target_width = int(target_height * aspect)
        github_logo = github_logo.resize((target_width, target_height), Image.Resampling.LANCZOS)

        if github_logo.mode != 'RGBA':
            github_logo = github_logo.convert('RGBA')
    else:
        print("Using generated GHSA badge")
        github_logo = create_ghsa_badge(120, 60)

    # Position: Between OSV (y~280) and CISA (y~360)
    # Looking at the diagram:
    # - OSV is around x=60, y=260
    # - CISA is around x=70, y=350
    # Place GitHub at approximately x=70, y=310

    # These coordinates are based on visual inspection of the diagram
    # OSV bottom edge is around y=305, CISA top edge is around y=340
    # We want to insert between them

    x_pos = 55  # Aligned with other left-side logos
    y_pos = 310  # Between OSV and CISA

    # Paste the logo onto the diagram
    diagram.paste(github_logo, (x_pos, y_pos), github_logo)

    # Now we need to add a label below the logo if using the GitHub mark
    if github_logo.height < 80:  # It's the downloaded logo, add "GHSA" label
        draw = ImageDraw.Draw(diagram)
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
        except:
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
            except:
                font = ImageFont.load_default()

        label = "GHSA"
        bbox = draw.textbbox((0, 0), label, font=font)
        label_width = bbox[2] - bbox[0]
        label_x = x_pos + (github_logo.width - label_width) // 2
        label_y = y_pos + github_logo.height + 2
        draw.text((label_x, label_y), label, fill=(36, 41, 47, 255), font=font)

    # Convert back to RGB for PNG saving (remove alpha if not needed)
    if output_path.suffix.lower() == '.png':
        # Keep RGBA for PNG
        pass
    else:
        diagram = diagram.convert('RGB')

    # Save the updated diagram
    diagram.save(output_path)
    print(f"Saved updated diagram to: {output_path}")


def main():
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    input_path = project_root / "FLOX_SEM_SCA_SBOM.png"
    output_path = project_root / "FLOX_SEM_SCA_SBOM.png"  # Overwrite original

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        exit(1)

    print(f"Updating architecture diagram: {input_path}")
    add_github_to_diagram(input_path, output_path)
    print("Done!")


if __name__ == '__main__':
    main()
