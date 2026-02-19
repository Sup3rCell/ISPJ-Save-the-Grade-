import io
import os
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.colors import Color
from pypdf import PdfReader, PdfWriter
from PIL import Image, ImageDraw, ImageFont, ImageEnhance

class WatermarkEngine:
    def __init__(self):
        pass

    def _create_pdf_watermark(self, text, width, height):
        """Creates a temporary PDF in memory with the watermark text."""
        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=(width, height))
        
        # Setup watermark style
        c.translate(width / 2, height / 2)
        c.rotate(45)
        c.setFillColor(Color(0.5, 0.5, 0.5, alpha=0.3)) # Grey, semi-transparent
        
        # Dynamic font size based on page width
        font_size = width / 10
        c.setFont("Helvetica-Bold", font_size)
        c.drawCentredString(0, 0, text)
        
        # Add a second line if needed (e.g. "CONFIDENTIAL")
        c.setFont("Helvetica", font_size / 2)
        c.drawCentredString(0, -font_size, "SECURE DOCUMENT")
        
        c.save()
        packet.seek(0)
        return packet

    def process_pdf(self, file_bytes, watermark_text):
        """Overlays watermark on an existing PDF."""
        try:
            # Read the original PDF
            original_pdf = PdfReader(io.BytesIO(file_bytes))
            output = PdfWriter()

            for i in range(len(original_pdf.pages)):
                page = original_pdf.pages[i]
                
                # Get page dimensions
                # pypdf pages might not have mediabox in all cases, handle gracefully
                try:
                    page_width = float(page.mediabox.width)
                    page_height = float(page.mediabox.height)
                except:
                    page_width, page_height = 595.27, 841.89 # Fallback to A4
                
                watermark_packet = self._create_pdf_watermark(watermark_text, page_width, page_height)
                watermark_pdf = PdfReader(watermark_packet)
                watermark_page = watermark_pdf.pages[0]
                
                # Merge
                page.merge_page(watermark_page)
                output.add_page(page)

            output_stream = io.BytesIO()
            output.write(output_stream)
            output_stream.seek(0)
            return output_stream.read()
            
        except Exception as e:
            print(f"PDF Watermarking Error: {e}")
            return file_bytes # Fallback to original

    def process_image(self, file_bytes, watermark_text):
        """Draws watermark on an image."""
        try:
            image = Image.open(io.BytesIO(file_bytes)).convert("RGBA")
            width, height = image.size
            
            # Create a transparent overlay
            overlay = Image.new('RGBA', image.size, (255, 255, 255, 0))
            draw = ImageDraw.Draw(overlay)
            
            # Font size relative to image width
            font_size = int(width / 20)
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except:
                font = ImageFont.load_default() 
                # Note: Default font doesn't support size in older PIL, but we'll try

            # Draw generic watermark pattern (grid)
            text = f"{watermark_text}\nSECURE DOCUMENT"
            
            # We want to rotate text. 
            # Strategy: Create a single text image, rotate it, and paste it repeatedly?
            # Or just one big centered watermark. Let's do one big centered one for simplicity and performance.
            
            # Temporary canvas for text
            text_img = Image.new('RGBA', (int(width*1.5), int(height*1.5)), (0,0,0,0))
            text_draw = ImageDraw.Draw(text_img)
            
            # Draw diagonal text
            cx, cy = text_img.size[0] // 2, text_img.size[1] // 2
            
            text_draw.text((cx, cy), text, font=font, fill=(128, 128, 128, 128), anchor="mm")
            
            # Rotate
            rotated = text_img.rotate(45, expand=False, center=(cx, cy))
            
            # Crop to image size
            left = (rotated.width - width) // 2
            top = (rotated.height - height) // 2
            
            watermark_layer = rotated.crop((left, top, left + width, top + height))
            
            # Composite
            out = Image.alpha_composite(image, watermark_layer)
            
            # Convert back to RGB for JPEG/PNG (if not transparent)
            # We'll return PNG to preserve quality
            output_stream = io.BytesIO()
            out.save(output_stream, format="PNG")
            return output_stream.getvalue()

        except Exception as e:
            print(f"Image Watermarking Error: {e}")
            return file_bytes

    def text_to_pdf(self, text_content, watermark_text):
        """Converts text content to a PDF with watermark."""
        try:
            packet = io.BytesIO()
            # Use A4 by default
            width, height = A4
            c = canvas.Canvas(packet, pagesize=A4)
            
            # Split text into lines
            try:
                text_content = text_content.decode('utf-8')
            except:
                pass # Already string
                
            lines = text_content.split('\n')
            
            y = height - 50
            line_height = 14
            
            c.setFont("Courier", 10)
            
            # Draw Watermark functionality as a helper to reuse on each page
            def draw_bg_watermark():
                c.saveState()
                c.translate(width / 2, height / 2)
                c.rotate(45)
                c.setFillColor(Color(0.8, 0.8, 0.8, alpha=0.5))
                c.setFont("Helvetica-Bold", 60)
                c.drawCentredString(0, 0, "CONFIDENTIAL")
                c.setFont("Helvetica", 20)
                c.drawCentredString(0, -30, watermark_text)
                c.restoreState()

            draw_bg_watermark()
            
            for line in lines:
                if y < 50:
                    c.showPage()
                    draw_bg_watermark()
                    c.setFont("Courier", 10)
                    y = height - 50
                
                # Simple wrapping or truncation
                c.drawString(50, y, line[:100]) # Truncate long lines to fit page width roughly
                y -= line_height
                
            c.save()
            packet.seek(0)
            return packet.read()
            
        except Exception as e:
            print(f"Text to PDF Error: {e}")
            return None # Return None to signal failure
