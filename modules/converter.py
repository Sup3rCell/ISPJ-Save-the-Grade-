import io
import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFont
import base64

class DocumentConverter:
    def __init__(self):
        pass

    def pdf_to_images(self, pdf_bytes):
        """
        Converts a PDF (bytes) into a list of base64 encoded PNG strings.
        Returns: [ "base64_string_page_1", "base64_string_page_2", ... ]
        """
        images_b64 = []
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                # Render high quality image (2x zoom for clarity)
                mat = fitz.Matrix(2, 2)
                pix = page.get_pixmap(matrix=mat)
                
                # Get bytes
                img_bytes = pix.tobytes("png")
                
                # Base64 encode
                b64_str = base64.b64encode(img_bytes).decode('utf-8')
                images_b64.append(b64_str)
            doc.close()
        except Exception as e:
            print(f"PDF to Image Conversion Error: {e}")
            return []
            
        return images_b64

    def text_to_images(self, text_content):
        """
        Converts text content into a list of base64 encoded PNG strings (pages).
        """
        images_b64 = []
        try:
            if isinstance(text_content, bytes):
                text_content = text_content.decode('utf-8', errors='replace')

            # Basic configuration
            # A4 size at 72dpi is approx 595x842. Let's do 2x for quality: 1190x1684
            page_width = 1190
            page_height = 1684
            margin = 100
            
            # Create a dummy image to load font
            dummy = Image.new('RGB', (1, 1))
            draw = ImageDraw.Draw(dummy)
            
            # Font setup
            font = None
            try:
                # Try to get a monospace font
                font = ImageFont.truetype("consola.ttf", 24)
            except:
                try:
                    font = ImageFont.truetype("arial.ttf", 24)
                except:
                    font = ImageFont.load_default()

            lines = text_content.split('\n')
            
            # Split lines into pages
            # Estimate lines per page
            # With 24px font + padding, say 30px line height
            line_height = 30
            # Calculate actual text height block
            usable_height = page_height - (margin * 2)
            lines_per_page = usable_height // line_height
            
            current_line_idx = 0
            
            # If empty file
            if not lines:
                lines = ["(Empty File)"]

            while current_line_idx < len(lines):
                # New Page
                img = Image.new('RGB', (page_width, page_height), 'white')
                draw = ImageDraw.Draw(img)
                
                # Draw text
                y = margin
                end_idx = min(current_line_idx + lines_per_page, len(lines))
                
                for i in range(current_line_idx, end_idx):
                    line = lines[i]
                    # Simple truncation for now, real wrapping is complex or requires textwrap module
                    # textwrap.wrap(line, width=100) could be used but complexity increases for pagination
                    draw.text((margin, y), line[:120], fill="black", font=font)
                    y += line_height
                
                current_line_idx = end_idx
                if current_line_idx == 0: # Avoid infinite loop if somehow 0
                    current_line_idx += 1
                
                # Save to bytes
                output_stream = io.BytesIO()
                img.save(output_stream, format="PNG")
                b64_str = base64.b64encode(output_stream.getvalue()).decode('utf-8')
                images_b64.append(b64_str)
                
        except Exception as e:
            print(f"Text to Image Conversion Error: {e}")
            # Return a simple error image?
            return []
            
        return images_b64

    def image_to_base64_list(self, image_bytes):
        """
        Just helps wrap existing images (JPG/PNG) into the same list format.
        """
        try:
             b64_str = base64.b64encode(image_bytes).decode('utf-8')
             return [b64_str]
        except Exception as e:
            print(f"Image Conversion Error: {e}")
            return []
