import React, { useState, useRef } from 'react';
import {
  FileSearch,
  Upload,
  AlertTriangle,
  CheckCircle,
  Clock,
  Camera,
  Cpu,
  Layers,
  Info,
  ShieldCheck,
  FileCode,
  Tag,
  RefreshCw,
  Search
} from 'lucide-react';
import { metadataService } from '../services/metadataService';
import { ledgerStorage } from '../services/ledgerStorage';

export default function MetadataIntelligence() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [metadata, setMetadata] = useState(null);
  const [isExtracting, setIsExtracting] = useState(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileUpload = async (file) => {
    if (!file) return;
    setSelectedFile(file);
    setIsExtracting(true);

    if (file.type.startsWith('image/')) {
      setPreviewUrl(URL.createObjectURL(file));
    } else {
      setPreviewUrl(null);
    }

    try {
      const extracted = await metadataService.extractMetadata(file);
      setMetadata(extracted);
    } catch (err) {
      console.error('Metadata extraction failed:', err);
    } finally {
      setIsExtracting(false);
    }
  };

  const handleDemoPreset = async (presetType) => {
    // Generate simulated preset file
    let simulatedName = 'satellite_recon_sample.jpg';
    if (presetType === 'photoshop') simulatedName = 'edited_defense_brief_photoshop.jpg';
    if (presetType === 'stripped') simulatedName = 'web_scraped_stripped.png';

    const dummyBlob = new Blob(['DEMO_METADATA_STREAM_BYTE_PAYLOAD'], { type: 'image/jpeg' });
    const dummyFile = new File([dummyBlob], simulatedName, {
      type: 'image/jpeg',
      lastModified: Date.now(),
    });

    await handleFileUpload(dummyFile);
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-background-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-accent text-xs font-mono uppercase tracking-wider mb-1">
            <FileSearch className="w-4 h-4" />
            <span>EXIF & Bitstream Metadata Forensics</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight">
            Metadata Intelligence
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Extract EXIF tags, software modification footprints, sensor signatures, and temporal timestamps to identify discrepancies without relying on metadata as sole proof of tampering.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Demo Presets:</span>
          <button
            onClick={() => handleDemoPreset('photoshop')}
            className="px-2.5 py-1 rounded bg-navy-850 hover:bg-navy-800 text-xs font-mono text-cyan-300 border border-background-border transition-colors"
          >
            Photoshop Stamp
          </button>
          <button
            onClick={() => handleDemoPreset('stripped')}
            className="px-2.5 py-1 rounded bg-navy-850 hover:bg-navy-800 text-xs font-mono text-amber-300 border border-background-border transition-colors"
          >
            Stripped EXIF
          </button>
        </div>
      </div>

      {/* Forensic Disclaimer Callout */}
      <div className="p-4 bg-navy-900/90 rounded-xl border border-cyan-500/20 flex items-start gap-3 text-xs text-slate-300 shadow-md">
        <Info className="w-5 h-5 text-cyan-accent flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">Forensic Triage Principle:</strong> Metadata is advisory evidence. It can be removed or forged without changing the primary visual image content. In SourceMark, mathematical proof of authenticity rests on the <span className="text-cyan-300 font-mono">SHA-256</span> bitstream hash and <span className="text-cyan-300 font-mono">Ed25519</span> signature, while metadata provides investigative context.
        </div>
      </div>

      {/* Upload Box */}
      <div
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
        }}
        className="border-2 border-dashed border-background-border hover:border-cyan-500/60 bg-navy-900/70 hover:bg-navy-900/95 rounded-2xl p-8 text-center cursor-pointer transition-all group shadow-lg"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*,.pdf,.txt,.docx"
          onChange={(e) => handleFileUpload(e.target.files?.[0])}
          className="hidden"
        />

        <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto mb-3 group-hover:scale-110 transition-transform">
          {isExtracting ? (
            <RefreshCw className="w-6 h-6 text-cyan-accent animate-spin" />
          ) : (
            <Upload className="w-6 h-6 text-cyan-accent" />
          )}
        </div>

        <h3 className="text-sm font-semibold text-white">
          {selectedFile ? selectedFile.name : 'Click to Upload Asset for Deep Metadata Extraction'}
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          Parses EXIF, XMP, JFIF, camera sensor parameters, and editing tool signatures client-side.
        </p>
      </div>

      {/* Extraction Results */}
      {metadata && (
        <div className="space-y-6 animate-fade-in">
          {/* Top Status Banner */}
          <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
            metadata.consistency === 'SUSPICIOUS'
              ? 'bg-rose-950/30 border-rose-500/40'
              : metadata.consistency === 'INCOMPLETE'
              ? 'bg-amber-950/30 border-amber-500/40'
              : 'bg-emerald-950/30 border-emerald-500/40'
          }`}>
            <div className="flex items-center gap-3">
              {metadata.consistency === 'SUSPICIOUS' ? (
                <AlertTriangle className="w-6 h-6 text-rose-400 flex-shrink-0" />
              ) : metadata.consistency === 'INCOMPLETE' ? (
                <Info className="w-6 h-6 text-amber-400 flex-shrink-0" />
              ) : (
                <CheckCircle className="w-6 h-6 text-emerald-400 flex-shrink-0" />
              )}
              <div>
                <div className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Metadata Evaluation: {metadata.consistency}
                </div>
                <div className="text-xs text-slate-300 mt-0.5">
                  {metadata.summary}
                </div>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[10px] text-slate-400 font-mono uppercase block">Anomalies Detected</span>
              <span className={`text-lg font-bold font-mono ${
                metadata.anomalies.length > 0 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {metadata.anomalies.length} Flag{metadata.anomalies.length === 1 ? '' : 's'}
              </span>
            </div>
          </div>

          {/* Anomaly Alerts List */}
          {metadata.anomalies.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Detected Forensic Observations
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {metadata.anomalies.map((anom, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-navy-900 border border-amber-500/30 rounded-lg flex items-start gap-2.5 text-xs text-slate-300"
                  >
                    <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-amber-300">{anom.field}:</span> {anom.message}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* 1. Basic File Info */}
            <div className="bg-navy-900/90 border border-background-border rounded-xl p-5 shadow-lg">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-background-border text-cyan-accent text-xs font-mono uppercase font-bold">
                <FileCode className="w-4 h-4" />
                <span>File Header Properties</span>
              </div>
              <div className="space-y-2.5 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono">File Name</span>
                  <span className="text-white font-medium break-all">{metadata.basic.name}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono">Byte Size</span>
                  <span className="text-white font-mono">{metadata.basic.sizeFormatted}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono">MIME Type</span>
                  <span className="text-cyan-300 font-mono">{metadata.basic.type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono">Filesystem Modified</span>
                  <span className="text-slate-300 font-mono">{metadata.basic.lastModified ? new Date(metadata.basic.lastModified).toLocaleString() : 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* 2. Visual Dimensions */}
            <div className="bg-navy-900/90 border border-background-border rounded-xl p-5 shadow-lg">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-background-border text-cyan-accent text-xs font-mono uppercase font-bold">
                <Camera className="w-4 h-4" />
                <span>Visual Geometry</span>
              </div>
              {metadata.dimensions ? (
                <div className="space-y-2.5 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Resolution</span>
                    <span className="text-white font-mono font-bold">
                      {metadata.dimensions.width} × {metadata.dimensions.height} px
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Aspect Ratio</span>
                    <span className="text-slate-300 font-mono">{metadata.dimensions.aspectRatio}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Megapixels</span>
                    <span className="text-cyan-300 font-mono">{metadata.dimensions.megapixels} MP</span>
                  </div>
                  {previewUrl && (
                    <div className="mt-2">
                      <span className="text-slate-400 block text-[10px] font-mono mb-1">Image Thumbnail</span>
                      <img src={previewUrl} alt="Preview" className="w-full h-20 object-cover rounded-md border border-background-border" />
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500 font-mono">
                  No visual pixel geometry (Non-image asset or vector file).
                </div>
              )}
            </div>

            {/* 3. EXIF & Sensor Details */}
            <div className="bg-navy-900/90 border border-background-border rounded-xl p-5 shadow-lg">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-background-border text-cyan-accent text-xs font-mono uppercase font-bold">
                <Tag className="w-4 h-4" />
                <span>Hardware & Software Tags</span>
              </div>
              {metadata.exifData ? (
                <div className="space-y-2.5 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Camera / Sensor Make</span>
                    <span className="text-white font-medium">{metadata.exifData.Make || metadata.exifData.Model || 'Generic / Sensor Masked'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Software Signature</span>
                    <span className={`font-mono ${
                      metadata.exifData.Software ? 'text-amber-300 font-semibold' : 'text-slate-400'
                    }`}>
                      {metadata.exifData.Software || 'None (No editing tool signature)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Capture Timestamp</span>
                    <span className="text-slate-300 font-mono">
                      {metadata.exifData.CreateDate || metadata.exifData.DateTimeOriginal || 'Not present in EXIF'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] font-mono">Color Space</span>
                    <span className="text-slate-300 font-mono">{metadata.exifData.ColorSpace || 'sRGB standard'}</span>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500 font-mono">
                  EXIF headers absent or scrubbed. Common in web-optimized or encrypted media.
                </div>
              )}
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

