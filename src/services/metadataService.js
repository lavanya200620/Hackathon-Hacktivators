/**
 * SourceMark Metadata Intelligence Service
 * Extracts client-side EXIF, IPTC, XMP, dimensions, and temporal correlation.
 * 
 * NOTE: Metadata can easily be stripped or spoofed by bad actors; 
 * missing metadata alone is NEVER treated as proof of tampering.
 */

import exifr from 'exifr';

export const metadataService = {
  /**
   * Parse deep metadata from file
   */
  async extractMetadata(file) {
    const basic = {
      name: file.name,
      size: file.size,
      sizeFormatted: this.formatBytes(file.size),
      type: file.type || 'application/octet-stream',
      lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : null,
      extension: file.name.split('.').pop().toLowerCase(),
    };

    let exifData = null;
    let dimensions = null;
    let anomalies = [];
    let consistency = 'CONSISTENT';

    // 1. If image, extract dimensions & EXIF
    if (file.type.startsWith('image/')) {
      try {
        dimensions = await this.getImageDimensions(file);
      } catch (e) {
        console.warn('Could not extract dimensions:', e);
      }

      try {
        exifData = await exifr.parse(file, {
          tiff: true,
          xmp: true,
          icc: false,
          jfif: true,
          ihdr: true,
        });
      } catch (e) {
        console.warn('EXIF parsing skipped or unsupported for file format:', e);
      }

      // 2. Perform Consistency & Anomaly Analysis
      if (!exifData || Object.keys(exifData).length === 0) {
        consistency = 'STRIPPED';
        anomalies.push({
          type: 'INFO',
          field: 'EXIF Header',
          message: 'EXIF metadata is stripped or absent. Note: This is standard for web exports and social messaging apps.',
        });
      } else {
        // Check for editing software tags (Photoshop, GIMP, etc.)
        const software = exifData.Software || exifData.ProcessingSoftware || '';
        if (software) {
          anomalies.push({
            type: 'FLAG',
            field: 'Software Attribution',
            message: `Software footprint detected in headers: "${software}". Indicates asset was processed in editor before export.`,
          });
        }

        // Compare creation date with filesystem modified date
        if (exifData.CreateDate && basic.lastModified) {
          const createTime = new Date(exifData.CreateDate).getTime();
          const modTime = new Date(basic.lastModified).getTime();
          // If filesystem last modified is significantly earlier than internal EXIF creation date
          if (modTime < createTime - 60000) {
            consistency = 'INCONSISTENT';
            anomalies.push({
              type: 'SUSPICIOUS',
              field: 'Timestamp Inversion',
              message: `Filesystem last modified date (${new Date(modTime).toISOString()}) precedes camera capture timestamp (${new Date(createTime).toISOString()}). Possible temporal manipulation.`,
            });
          }
        }
      }
    } else {
      // Document / non-image
      consistency = 'CONSISTENT';
    }

    return {
      basic,
      dimensions,
      exif: exifData,
      consistency,
      anomalies,
      extractedAt: new Date().toISOString(),
      disclaimer: 'Metadata extraction is informational only. Metadata can be modified, stripped, or spoofed without modifying image pixel data.',
    };
  },

  getImageDimensions(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        resolve({
          width: img.width,
          height: img.height,
          aspectRatio: (img.width / img.height).toFixed(2),
          megapixels: ((img.width * img.height) / 1000000).toFixed(2) + ' MP',
        });
        URL.revokeObjectURL(url);
      };
      img.onerror = (e) => {
        URL.revokeObjectURL(url);
        reject(e);
      };
      img.src = url;
    });
  },

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
};

