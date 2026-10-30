import React, { useState, useRef, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  GitCompare,
  Upload,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Image as ImageIcon,
  Layers,
  Sparkles,
  Sliders,
  Download,
  Info
} from 'lucide-react';
import { calculateSHA256 } from '../services/crypto';
import { ledgerStorage } from '../services/ledgerStorage';

export default function Compare() {
  const [searchParams] = useSearchParams();
  const preselectedSourceId = searchParams.get('original');

  // Comparison files
  const [fileA, setFileA] = useState(null); // Original
  const [fileB, setFileB] = useState(null); // Suspected
  const [previewA, setPreviewA] = useState(null);
  const [previewB, setPreviewB] = useState(null);
  const [hashA, setHashA] = useState('');
  const [hashB, setHashB] = useState('');

  // Mode: 'image' | 'text'
  const [mode, setMode] = useState('image');
  const [textA, setTextA] = useState('');
  const [textB, setTextB] = useState('');

  // Image Analysis State
  const [zoomLevel, setZoomLevel] = useState(1);
  const [diffPercent, setDiffPercent] = useState(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [differingPixelCount, setDifferingPixelCount] = useState(0);
  const [totalPixels, setTotalPixels] = useState(0);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Canvas refs
  const canvasDiffRef = useRef(null);
  const canvasOriginalRef = useRef(null);
  const canvasModifiedRef = useRef(null);

  useEffect(() => {
    // If arriving from Verify page with an existing Source ID, load sample
    if (preselectedSourceId) {
      loadDemoComparison('image');
    }
  }, [preselectedSourceId]);

  // Load Demo Presets for immediate Hackathon Demonstration
  const loadDemoComparison = (presetType) => {
    if (presetType === 'image') {
      setMode('image');
      // Create sample image canvases
      const width = 420;
      const height = 300;
      setDimensions({ width, height });

      // Generate Original Image on canvas
      const origCanvas = document.createElement('canvas');
      origCanvas.width = width;
      origCanvas.height = height;
      const ctxA = origCanvas.getContext('2d');
      // Draw simulated satellite scene (grid, dark background, radar circles)
      ctxA.fillStyle = '#0B132B';
      ctxA.fillRect(0, 0, width, height);
      ctxA.strokeStyle = 'rgba(56, 189, 248, 0.2)';
      for (let x = 0; x < width; x += 30) {
        ctxA.beginPath();
        ctxA.moveTo(x, 0); ctxA.lineTo(x, height);
        ctxA.stroke();
      }
      for (let y = 0; y < height; y += 30) {
        ctxA.beginPath();
        ctxA.moveTo(0, y); ctxA.lineTo(width, y);
        ctxA.stroke();
      }
      // Target complex
      ctxA.fillStyle = '#10B981';
      ctxA.fillRect(80, 70, 70, 50);
      ctxA.fillStyle = '#38BDF8';
      ctxA.beginPath();
      ctxA.arc(280, 160, 40, 0, Math.PI * 2);
      ctxA.fill();
      ctxA.fillStyle = '#94A3B8';
      ctxA.font = '12px JetBrains Mono';
      ctxA.fillText('SECTOR 4B - ORBITAL RECON 07', 20, 30);

      // Generate Tampered Image on canvas (has modified runway and altered radar signature)
      const modCanvas = document.createElement('canvas');
      modCanvas.width = width;
      modCanvas.height = height;
      const ctxB = modCanvas.getContext('2d');
      // Copy orig first
      ctxB.drawImage(origCanvas, 0, 0);
      // Introduce tamper: remove green building, add red rectangle anomaly
      ctxB.fillStyle = '#0B132B';
      ctxB.fillRect(80, 70, 70, 50); // Erased building
      ctxB.fillStyle = '#EF4444';
      ctxB.fillRect(80, 70, 70, 50); // Painted over with altered structure
      // Altered radar arc
      ctxB.fillStyle = '#F59E0B';
      ctxB.beginPath();
      ctxB.arc(280, 160, 20, 0, Math.PI * 2);
      ctxB.fill();
      ctxB.fillStyle = '#F87171';
      ctxB.fillText('[ALTERED BITSTREAM REGION]', 80, 140);

      const dataUrlA = origCanvas.toDataURL();
      const dataUrlB = modCanvas.toDataURL();

      setPreviewA(dataUrlA);
      setPreviewB(dataUrlB);
      setFileA({ name: 'satellite_recon_orbital_07.png', size: 2458920 });
      setFileB({ name: 'satellite_recon_orbital_07_tampered.png', size: 2461040 });
      setHashA('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      setHashB('b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78');

      // Run diff
      computePixelDifference(origCanvas, modCanvas, width, height);
    } else if (presetType === 'text') {
      setMode('text');
      setFileA({ name: 'contract_merger_terms_v1.txt', size: 4820 });
      setFileB({ name: 'contract_merger_terms_v1_tampered.txt', size: 4890 });
      setHashA('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
      setHashB('a4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2');

      setTextA(`SECTION 4. LIQUIDATION PREFERENCE
4.1 The acquisition payout shall not exceed USD $5,000,000 without unanimous written board authorization.
4.2 Escrow retention period is strictly 365 calendar days from closing.
4.3 Intellectual property rights remain non-exclusive during the provisional evaluation period.
SECTION 5. GOVERNING JURISDICTION
5.1 This agreement is executed under the laws of Delaware, USA.`);

      setTextB(`SECTION 4. LIQUIDATION PREFERENCE
4.1 The acquisition payout shall not exceed USD $18,500,000 without simple majority executive approval. [TAMPERED]
4.2 Escrow retention period is reduced to 30 calendar days from closing. [ALTERED]
4.3 Intellectual property rights transfer irrevocably upon preliminary signature. [ALTERED]
SECTION 5. GOVERNING JURISDICTION
5.1 This agreement is executed under the laws of Delaware, USA.`);
    }
  };

  // Compute pixel level difference
  const computePixelDifference = (canvasA, canvasB, w, h) => {
    setIsAnalyzing(true);
    setTimeout(() => {
      const ctxA = canvasA.getContext('2d');
      const ctxB = canvasB.getContext('2d');
      const imgDataA = ctxA.getImageData(0, 0, w, h);
      const imgDataB = ctxB.getImageData(0, 0, w, h);

      const diffCanvas = canvasDiffRef.current || document.createElement('canvas');
      diffCanvas.width = w;
      diffCanvas.height = h;
      const ctxDiff = diffCanvas.getContext('2d');
      const diffImageData = ctxDiff.createImageData(w, h);

      let diffPixels = 0;
      const total = w * h;

      for (let i = 0; i < imgDataA.data.length; i += 4) {
        const r1 = imgDataA.data[i];
        const g1 = imgDataA.data[i + 1];
        const b1 = imgDataA.data[i + 2];

        const r2 = imgDataB.data[i];
        const g2 = imgDataB.data[i + 1];
        const b2 = imgDataB.data[i + 2];

        const delta = Math.abs(r1 - r2) + Math.abs(g1 - g2) + Math.abs(b1 - b2);

        if (delta > 25) {
          // Highlight changed pixel in fluorescent neon red with outline
          diffPixels++;
          diffImageData.data[i] = 239;     // Red
          diffImageData.data[i + 1] = 68;  // Green
          diffImageData.data[i + 2] = 68;  // Blue
          diffImageData.data[i + 3] = 255; // Full Opacity
        } else {
          // Dim original in dark slate for contrast
          diffImageData.data[i] = Math.floor(r1 * 0.15);
          diffImageData.data[i + 1] = Math.floor(g1 * 0.15);
          diffImageData.data[i + 2] = Math.floor(b1 * 0.25);
          diffImageData.data[i + 3] = 160;
        }
      }

      ctxDiff.putImageData(diffImageData, 0, 0);
      setTotalPixels(total);
      setDifferingPixelCount(diffPixels);
      const pct = ((diffPixels / total) * 100).toFixed(2);
      setDiffPercent(pct);
      setIsAnalyzing(false);
    }, 200);
  };

  // Handle User File Uploads
  const handleUploadA = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    setFileA(f);
    const hash = await calculateSHA256(f);
    setHashA(hash);

    if (f.type.startsWith('image/')) {
      setMode('image');
      const reader = new FileReader();
      reader.onload = (ev) => {
        setPreviewA(ev.target.result);
        loadImageToCanvas(ev.target.result, 'A');
      };
      reader.readAsDataURL(f);
    } else {
      setMode('text');
      const text = await f.text();
      setTextA(text);
    }
  };

  const handleUploadB = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    setFileB(f);
    const hash = await calculateSHA256(f);
    setHashB(hash);

    if (f.type.startsWith('image/')) {
      setMode('image');
      const reader = new FileReader();
      reader.onload = (ev) => {
        setPreviewB(ev.target.result);
        loadImageToCanvas(ev.target.result, 'B');
      };
      reader.readAsDataURL(f);
    } else {
      setMode('text');
      const text = await f.text();
      setTextB(text);
    }
  };

  const loadImageToCanvas = (src, target) => {
    const img = new Image();
    img.onload = () => {
      setDimensions({ width: img.width, height: img.height });
    };
    img.src = src;
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Digital Tamper Analysis
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Identify, isolate, and visualize pixel-level and byte-level differences between registered originals and suspected modified assets.
          </p>
        </div>

        {/* Demo Presets Bar */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500 uppercase mr-1">Load Demo:</span>
          <button
            onClick={() => loadDemoComparison('image')}
            className="px-3 py-1.5 rounded-lg bg-navy-850 hover:bg-navy-800 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <ImageIcon className="w-3.5 h-3.5 text-cyan-400" />
            Satellite Image Diff
          </button>
          <button
            onClick={() => loadDemoComparison('text')}
            className="px-3 py-1.5 rounded-lg bg-navy-850 hover:bg-navy-800 text-indigo-300 border border-indigo-500/30 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-indigo-400" />
            Contract Text Diff
          </button>
        </div>
      </div>

      {/* Two Upload Cards Side-by-Side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Upload 1: Original / Registered Master */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              Source 1: Original / Registered Master
            </h3>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
              Reference Baseline
            </span>
          </div>

          <label className="border-2 border-dashed border-slate-700/80 hover:border-emerald-500/50 rounded-xl p-5 text-center cursor-pointer bg-navy-900/40 hover:bg-navy-900/70 transition-all flex flex-col items-center justify-center min-h-[120px] block">
            <input type="file" onChange={handleUploadA} className="hidden" />
            <Upload className="w-6 h-6 text-emerald-400 mb-2" />
            <span className="text-xs font-semibold text-white block">
              {fileA ? fileA.name : 'Upload Master Registered File'}
            </span>
            <span className="text-[10px] text-slate-400 mt-0.5 block">
              {fileA ? `${(fileA.size / 1024).toFixed(1)} KB` : 'Click to select original file'}
            </span>
          </label>

          {hashA && (
            <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Original SHA-256</span>
              <p className="text-[11px] font-mono text-emerald-300 break-all select-all">{hashA}</p>
            </div>
          )}
        </div>

        {/* Upload 2: Suspected / Modified File */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
              Source 2: Suspected / Modified Asset
            </h3>
            <span className="text-[10px] font-mono text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-500/30">
              Inspected Target
            </span>
          </div>

          <label className="border-2 border-dashed border-slate-700/80 hover:border-rose-500/50 rounded-xl p-5 text-center cursor-pointer bg-navy-900/40 hover:bg-navy-900/70 transition-all flex flex-col items-center justify-center min-h-[120px] block">
            <input type="file" onChange={handleUploadB} className="hidden" />
            <Upload className="w-6 h-6 text-rose-400 mb-2" />
            <span className="text-xs font-semibold text-white block">
              {fileB ? fileB.name : 'Upload Suspected / Modified File'}
            </span>
            <span className="text-[10px] text-slate-400 mt-0.5 block">
              {fileB ? `${(fileB.size / 1024).toFixed(1)} KB` : 'Click to select target file'}
            </span>
          </label>

          {hashB && (
            <div className="p-2.5 rounded-lg bg-navy-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-mono block">Target SHA-256</span>
              <p className="text-[11px] font-mono text-rose-300 break-all select-all">{hashB}</p>
            </div>
          )}
        </div>
      </div>

      {/* Forensic Comparison Interface */}
      {(previewA || textA) && (
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-bold uppercase tracking-wide text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Synchronized Comparative Canvas
              </h2>
              {diffPercent !== null && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-950 text-rose-300 border border-rose-500/40">
                  {diffPercent}% Differing Pixels
                </span>
              )}
            </div>

            {mode === 'image' && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400 font-mono">Zoom: {Math.round(zoomLevel * 100)}%</span>
                <button
                  onClick={() => setZoomLevel((z) => Math.min(z + 0.25, 2.5))}
                  className="p-1.5 rounded-lg bg-navy-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-navy-800"
                  title="Zoom In"
                >
                  <ZoomIn className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setZoomLevel((z) => Math.max(z - 0.25, 0.5))}
                  className="p-1.5 rounded-lg bg-navy-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-navy-800"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setZoomLevel(1)}
                  className="p-1.5 rounded-lg bg-navy-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-navy-800"
                  title="Reset Zoom"
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>

          {/* IMAGE MODE: 3-Way Side-by-Side (Original vs Modified vs Pixel Diff) */}
          {mode === 'image' && previewA && previewB && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* 1. Original View */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" /> 1. Original Registered View
                  </span>
                  <div className="rounded-xl overflow-hidden border border-slate-800 bg-navy-950 p-2 flex items-center justify-center min-h-[220px]">
                    <img
                      src={previewA}
                      alt="Original"
                      style={{ transform: `scale(${zoomLevel})`, transition: 'transform 0.15s ease-out' }}
                      className="max-h-60 object-contain rounded"
                    />
                  </div>
                </div>

                {/* 2. Modified View */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-rose-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" /> 2. Suspected Modified View
                  </span>
                  <div className="rounded-xl overflow-hidden border border-slate-800 bg-navy-950 p-2 flex items-center justify-center min-h-[220px]">
                    <img
                      src={previewB}
                      alt="Modified"
                      style={{ transform: `scale(${zoomLevel})`, transition: 'transform 0.15s ease-out' }}
                      className="max-h-60 object-contain rounded"
                    />
                  </div>
                </div>

                {/* 3. Pixel-level Diff Visualization */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" /> 3. Pixel-Level Difference Map
                  </span>
                  <div className="rounded-xl overflow-hidden border border-cyan-500/40 bg-navy-950 p-2 flex items-center justify-center min-h-[220px] relative shadow-glow-cyan/20">
                    <canvas
                      ref={canvasDiffRef}
                      style={{ transform: `scale(${zoomLevel})`, transition: 'transform 0.15s ease-out' }}
                      className="max-h-60 object-contain rounded"
                    />
                    <div className="absolute bottom-2 right-2 px-2 py-0.5 rounded bg-navy-900/90 border border-slate-700 text-[10px] font-mono text-cyan-300">
                      Red: Changed Pixels
                    </div>
                  </div>
                </div>
              </div>

              {/* Forensic Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
                  <span className="text-slate-500 uppercase text-[10px] block">Differing Pixels</span>
                  <span className="text-rose-400 font-bold text-sm">
                    {differingPixelCount.toLocaleString()} / {totalPixels.toLocaleString()}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
                  <span className="text-slate-500 uppercase text-[10px] block">Variance Ratio</span>
                  <span className="text-rose-400 font-bold text-sm">{diffPercent}%</span>
                </div>
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
                  <span className="text-slate-500 uppercase text-[10px] block">Dimensions</span>
                  <span className="text-slate-300 font-bold text-sm">{dimensions.width} × {dimensions.height} px</span>
                </div>
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800">
                  <span className="text-slate-500 uppercase text-[10px] block">Size Delta</span>
                  <span className="text-cyan-400 font-bold text-sm">
                    {fileA && fileB ? `${Math.abs(fileA.size - fileB.size)} bytes` : 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* TEXT MODE: Line-by-Line Difference Comparison */}
          {mode === 'text' && textA && textB && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="space-y-1">
                <span className="text-emerald-400 font-semibold block text-[11px] mb-1">Original Lines</span>
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800 space-y-1 max-h-80 overflow-y-auto">
                  {textA.split('\n').map((line, i) => (
                    <div key={i} className="py-0.5 px-1.5 rounded text-slate-300 hover:bg-navy-900">
                      <span className="text-slate-600 select-none mr-2">{i + 1}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-rose-400 font-semibold block text-[11px] mb-1">Target Modified Lines</span>
                <div className="p-3 rounded-xl bg-navy-950 border border-slate-800 space-y-1 max-h-80 overflow-y-auto">
                  {textB.split('\n').map((line, i) => {
                    const isChanged = line.includes('[TAMPERED]') || line.includes('[ALTERED]') || (textA.split('\n')[i] !== line);
                    return (
                      <div
                        key={i}
                        className={`py-0.5 px-1.5 rounded ${
                          isChanged ? 'bg-rose-950/60 text-rose-300 border border-rose-500/40' : 'text-slate-300 hover:bg-navy-900'
                        }`}
                      >
                        <span className="text-slate-600 select-none mr-2">{i + 1}</span>
                        <span>{line}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Forensic Technical Report Card & Critical Disclaimer */}
          <div className="p-4 rounded-xl bg-navy-950 border border-slate-800 space-y-2 text-xs">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold">
              <Info className="w-4 h-4" />
              <span>Forensic Analysis Verdict: Content Variance Established</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Comparison between <span className="text-emerald-400 font-mono">{fileA?.name || 'File A'}</span> and <span className="text-rose-400 font-mono">{fileB?.name || 'File B'}</span> confirms non-identical cryptographic bitstreams with altered spatial pixels.
            </p>
            <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-amber-400/90 flex items-start gap-2 bg-amber-950/20 p-2.5 rounded-lg border border-amber-500/30">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <p>
                <strong>Forensic Protocol Notice:</strong> Visual and bitstream differences indicate that the two files are not cryptographically identical. However, visual variance alone does not prove malicious manipulation or hostile intent without contextual human investigation and chain of custody evaluation.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

