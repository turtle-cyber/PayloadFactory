// Radar.tsx
import React, { useRef, useEffect } from "react";
import { icon } from "../helpers/assetExport";

const FULL_CIRCLE = true; // false => semicircle (-90..90). true => full circle (-180..180)
const SWEEP_SEC = 5.6; // seconds per sweep (start->end)
const RING_COUNT = 4;
const FADE_ALPHA = 0.045; // smaller -> longer trails
const TARGET_FPS = 120; // throttle drawing to ~45fps for low CPU (set lower if needed)

type DotDef = {
  angleDeg: number; // 0 = up; positive to right
  radiusFrac: number; // fraction of outer radius
  baseSize: number;
  lastFlashAt: number;
};

const Radar: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const imgRef = useRef<HTMLImageElement | null>(null);

  // cached / precomputed geometry for frames
  const geomRef = useRef({
    width: 0,
    height: 0,
    cx: 0,
    cy: 0,
    outerMost: 0,
    ringRadii: [] as number[],
    dots: [] as DotDef[],
  });

  useEffect(() => {
    const canvas = canvasRef.current!;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    // cap DPR for performance but still look crisp
    const getDpr = () => Math.min(window.devicePixelRatio || 1, 2);

    // initial dots (angles and ring positions) — tweak these to place dots where you want
    const initialDots: DotDef[] = [
      { angleDeg: -62, radiusFrac: 0.78, baseSize: 7, lastFlashAt: 0 },
      { angleDeg: -14, radiusFrac: 0.64, baseSize: 6, lastFlashAt: 0 },
      { angleDeg: 38, radiusFrac: 0.56, baseSize: 5, lastFlashAt: 0 },
      { angleDeg: -40, radiusFrac: 0.36, baseSize: 8, lastFlashAt: 0 },
      { angleDeg: -40, radiusFrac: 0.96, baseSize: 3, lastFlashAt: 0 },
    ];

    // resize handler: recompute geometry in CSS pixels, convert dots -> positions
    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = getDpr();
      const cssW = rect.width;
      const cssH = rect.width * 0.5; // keep semicircle aspect
      canvas.width = Math.max(1, Math.round(cssW * dpr));
      canvas.height = Math.max(1, Math.round(cssH * dpr));
      canvas.style.width = `${cssW}px`;
      canvas.style.height = `${cssH}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // work in CSS pixels
      // compute geometry
      const cx = cssW / 2;
      const cy = cssH; // bottom center
      const outerMost = Math.min(cssW, cssH * 2) * 0.46; // fits nicely
      // ring radii (fractions of outerMost) — match visual layout; beam uses outerMost exactly
      const ringFractions = [1.0, 0.78, 0.56, 0.34];
      const ringRadii = ringFractions.map((f) => outerMost * f);
      // assign geometry
      geomRef.current.width = cssW;
      geomRef.current.height = cssH;
      geomRef.current.cx = cx;
      geomRef.current.cy = cy;
      geomRef.current.outerMost = outerMost;
      geomRef.current.ringRadii = ringRadii;
      // reinitialize dots (we keep their angles but compute sizes scaled)
      geomRef.current.dots = initialDots.map((d) => ({ ...d, lastFlashAt: 0 }));
      // clear canvas (keep transparent)
      ctx.clearRect(0, 0, cssW, cssH);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    // helpers
    const degToRad = (d: number) => (d * Math.PI) / 180;
    const nowMs = () => performance.now();

    // smooth easing function for dot flash (fade out)
    const pulseEase = (t: number) =>
      1 - Math.pow(1 - Math.min(Math.max(t, 0), 1), 2.4);

    // frame throttling
    const frameInterval = 1000 / TARGET_FPS;
    let lastFrameTime = 0;

    // sweep parameters
    const startAngle = FULL_CIRCLE ? -180 : -90;
    const endAngle = FULL_CIRCLE ? 180 : 90;
    const sweepRange = endAngle - startAngle;
    const sweepDuration = SWEEP_SEC;
    let sweepStartTime = performance.now();

    function drawRings() {
      const { cx, cy, ringRadii } = geomRef.current;
      ctx.save();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "rgba(255,255,255,0.06)";
      ringRadii.forEach((r) => {
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, 0, false);
        ctx.stroke();
      });
      ctx.restore();
    }

    // Draw center icon with circular background
    function drawCenterIcon() {
      const { cx, cy, outerMost } = geomRef.current;
      const r = outerMost;

      // Position at center bottom (radar origin)
      const centerX = cx;
      const centerY = cy;

      // Icon container size (scales with radar)
      const containerRadius = Math.max(28, (r / 420) * 38);

      ctx.save();

      // Outer glow effect
      ctx.beginPath();
      ctx.fillStyle = "rgba(255,40,40,0.15)";
      ctx.shadowColor = "rgba(255,40,40,0.5)";
      ctx.shadowBlur = 30;
      ctx.arc(centerX, centerY, containerRadius + 8, 0, Math.PI * 2);
      ctx.fill();

      // Main circular background (dark with subtle red tint)
      ctx.shadowBlur = 0;
      ctx.beginPath();
      const gradient = ctx.createRadialGradient(
        centerX,
        centerY - containerRadius * 0.3,
        0,
        centerX,
        centerY,
        containerRadius
      );
      gradient.addColorStop(0, "rgba(60,20,20,0.95)");
      gradient.addColorStop(0.5, "rgba(40,15,15,0.95)");
      gradient.addColorStop(1, "rgba(25,10,10,0.95)");
      ctx.fillStyle = gradient;
      ctx.arc(centerX, centerY, containerRadius, 0, Math.PI * 2);
      ctx.fill();

      // Subtle border ring
      ctx.beginPath();
      ctx.strokeStyle = "rgba(255,60,60,0.3)";
      ctx.lineWidth = 2;
      ctx.arc(centerX, centerY, containerRadius, 0, Math.PI * 2);
      ctx.stroke();

      // Inner highlight ring
      ctx.beginPath();
      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.lineWidth = 1;
      ctx.arc(centerX, centerY, containerRadius - 3, 0, Math.PI * 2);
      ctx.stroke();

      // Draw the icon image if loaded, otherwise draw placeholder
      const imgEl = imgRef.current;
      if (imgEl && imgEl.complete && imgEl.naturalWidth > 0) {
        const iconSize = containerRadius * 1.3;
        ctx.drawImage(
          imgEl,
          centerX - iconSize / 2,
          centerY - iconSize / 2,
          iconSize,
          iconSize
        );
      } else {
        // Placeholder: draw a simple robot/scan icon
        drawPlaceholderIcon(centerX, centerY, containerRadius * 0.6);
      }

      ctx.restore();
    }

    // Simple placeholder icon (can be replaced with actual image)
    function drawPlaceholderIcon(x: number, y: number, size: number) {
      ctx.save();
      ctx.strokeStyle = "rgba(255,255,255,0.7)";
      ctx.fillStyle = "rgba(255,255,255,0.7)";
      ctx.lineWidth = 2;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";

      // Draw a simple "scan" / "target" icon
      const s = size;

      // Outer brackets/corners
      ctx.beginPath();
      // Top-left corner
      ctx.moveTo(x - s * 0.7, y - s * 0.4);
      ctx.lineTo(x - s * 0.7, y - s * 0.7);
      ctx.lineTo(x - s * 0.4, y - s * 0.7);
      // Top-right corner
      ctx.moveTo(x + s * 0.4, y - s * 0.7);
      ctx.lineTo(x + s * 0.7, y - s * 0.7);
      ctx.lineTo(x + s * 0.7, y - s * 0.4);
      // Bottom-right corner
      ctx.moveTo(x + s * 0.7, y + s * 0.4);
      ctx.lineTo(x + s * 0.7, y + s * 0.7);
      ctx.lineTo(x + s * 0.4, y + s * 0.7);
      // Bottom-left corner
      ctx.moveTo(x - s * 0.4, y + s * 0.7);
      ctx.lineTo(x - s * 0.7, y + s * 0.7);
      ctx.lineTo(x - s * 0.7, y + s * 0.4);
      ctx.stroke();

      // Center dot
      ctx.beginPath();
      ctx.arc(x, y, s * 0.15, 0, Math.PI * 2);
      ctx.fill();

      // Crosshair lines
      ctx.beginPath();
      ctx.moveTo(x, y - s * 0.35);
      ctx.lineTo(x, y - s * 0.2);
      ctx.moveTo(x, y + s * 0.2);
      ctx.lineTo(x, y + s * 0.35);
      ctx.moveTo(x - s * 0.35, y);
      ctx.lineTo(x - s * 0.2, y);
      ctx.moveTo(x + s * 0.2, y);
      ctx.lineTo(x + s * 0.35, y);
      ctx.stroke();

      ctx.restore();
    }

    function frame(t: number) {
      const elapsed = (t - sweepStartTime) / 1000;
      const loop = (elapsed / sweepDuration) % 1;
      const beamAngleDeg = startAngle + loop * sweepRange;
      const beamAngleRad = degToRad(beamAngleDeg);

      // throttle frames for low CPU
      if (t - lastFrameTime < frameInterval) {
        rafRef.current = requestAnimationFrame(frame);
        return;
      }
      lastFrameTime = t;

      const {
        width: cssW,
        height: cssH,
        cx,
        cy,
        outerMost,
        ringRadii,
      } = geomRef.current;
      const r = outerMost; // beam length equals outerMost (matching outer ring)
      // FADE: destination-out (preserves transparency) with small alpha to create subtle trail
      ctx.save();
      ctx.globalCompositeOperation = "destination-out";
      ctx.fillStyle = `rgba(0,0,0,${FADE_ALPHA})`;
      ctx.fillRect(0, 0, cssW, cssH);
      ctx.restore();

      // draw beam (subtle gradual gradient)
      ctx.save();
      ctx.translate(cx, cy);

      // tip coordinates
      const tipX = Math.sin(beamAngleRad) * r;
      const tipY = -Math.cos(beamAngleRad) * r;

      // create gradual, smooth linear gradient
      const grad = ctx.createLinearGradient(0, 0, tipX, tipY);
      grad.addColorStop(0.0, "rgba(255,60,60,0.00)");
      grad.addColorStop(0.1, "rgba(255,60,60,0.02)");
      grad.addColorStop(0.25, "rgba(255,50,50,0.04)");
      grad.addColorStop(0.45, "rgba(255,40,40,0.08)");
      grad.addColorStop(0.6, "rgba(255,30,30,0.14)");
      grad.addColorStop(0.75, "rgba(255,30,30,0.22)");
      grad.addColorStop(0.85, "rgba(255,30,30,0.28)");
      grad.addColorStop(1.0, "rgba(255,40,40,0.10)");

      // beam widths (subtle)
      const beamW = Math.max(3, (r / 420) * 8); // slimmer scanner for subtle look

      // soft glow stroke
      ctx.rotate(beamAngleRad);
      ctx.globalCompositeOperation = "lighter"; // additive for subtle glow
      ctx.beginPath();
      ctx.lineWidth = beamW * 1.15;
      ctx.lineCap = "round";
      ctx.strokeStyle = grad;
      ctx.moveTo(0, 0);
      ctx.lineTo(0, -r);
      ctx.stroke();

      // core line with lower opacity
      ctx.beginPath();
      ctx.lineWidth = Math.max(1.2, beamW * 0.38);
      ctx.strokeStyle = "rgba(255,40,40,0.24)";
      ctx.moveTo(0, 0);
      ctx.lineTo(0, -r);
      ctx.stroke();

      // tip: small soft glow + tiny white core
      ctx.beginPath();
      const tipRadius = Math.max(3, (r / 420) * 8);
      ctx.fillStyle = "rgba(255,80,80,0.55)";
      ctx.shadowColor = "rgba(255,40,40,0.36)";
      ctx.shadowBlur = 12;
      ctx.arc(0, -r, tipRadius, 0, Math.PI * 2);
      ctx.fill();

      ctx.shadowBlur = 0;
      ctx.fillStyle = "rgba(255,255,255,0.75)";
      ctx.beginPath();
      ctx.arc(0, -r, Math.max(1.2, tipRadius * 0.28), 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();

      // draw rings on top (so they remain crisp)
      drawRings();

      // dots: compute and draw; flash when beam near dot angle
      const dots = geomRef.current.dots;
      const timeNow = nowMs();
      dots.forEach((d) => {
        const dotRad = degToRad(d.angleDeg);
        const dr = d.radiusFrac * r;
        const dx = cx + Math.sin(dotRad) * dr;
        const dy = cy - Math.cos(dotRad) * dr;

        // angular diff in degrees normalized 0..180
        let angDiff = Math.abs(((beamAngleDeg - d.angleDeg + 540) % 360) - 180);
        const THRESH = FULL_CIRCLE ? 3.5 : 3.6;
        if (angDiff <= THRESH && timeNow - d.lastFlashAt > 140) {
          d.lastFlashAt = timeNow;
        }

        // ease the flash intensity based on lastFlashAt
        const age = (timeNow - d.lastFlashAt) / 1000; // seconds
        let intensity = 0.04; // base subtle presence
        if (age < 0.6) {
          intensity = 0.12 + pulseEase(1 - age / 0.6) * 0.88; // peaks near 1, fades to base
        }

        // draw glow + core
        ctx.save();
        ctx.globalAlpha = Math.min(1, intensity);
        ctx.beginPath();
        ctx.fillStyle = "rgba(255,255,255,0.95)";
        ctx.shadowColor = `rgba(255,80,80,${0.6 * Math.min(1, intensity)})`;
        ctx.shadowBlur = 10 * Math.min(1, intensity);
        ctx.arc(dx, dy, d.baseSize, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      });

      // Draw center icon (always on top)
      drawCenterIcon();

      rafRef.current = requestAnimationFrame(frame);
    }

    // start animation
    rafRef.current = requestAnimationFrame(frame);

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      ro.disconnect();
    };
  }, []);

  // canvas is transparent (page background shows through)
  return (
    <div
      style={{
        width: "100%",
        display: "flex",
        justifyContent: "center",
        paddingTop: "10px",
      }}
    >
      {/* Hidden image element for the center icon */}
      <img ref={imgRef} src={icon} alt="" style={{ display: "none" }} />
      <canvas
        ref={canvasRef}
        style={{
          width: "min(94vw, 900px)",
          height: "min(47vw, 450px)",
          display: "block",
          borderRadius: 6,
          pointerEvents: "none",
          background: "transparent",
        }}
      />
    </div>
  );
};

export default Radar;
