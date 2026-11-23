import React from 'react';
import {
  AbsoluteFill,
  Composition,
  Img,
  Sequence,
  Easing,
  interpolate,
  staticFile,
  useCurrentFrame,
} from 'remotion';

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
export const TOTAL = 720;
export const SHOTS = [
  { id: 'open', label: 'DeepIntel · opening', from: 0, duration: 100 },
  { id: 'dashboard', label: 'Dashboard · risk explanation', from: 82, duration: 280 },
  { id: 'popup', label: 'Extension · browser verdict', from: 344, duration: 192 },
  { id: 'warning', label: 'Extension · onion warning', from: 518, duration: 138 },
  { id: 'close', label: 'DeepIntel · end card', from: 638, duration: 82 },
] as const;

const ease = Easing.bezier(0.2, 0.78, 0.24, 1);
const clamp = { extrapolateLeft: 'clamp' as const, extrapolateRight: 'clamp' as const };

const ProductFonts: React.FC = () => (
  <style>{`
    @font-face { font-family: 'DM Sans'; src: url('${staticFile('fonts/dm-sans-latin.woff2')}') format('woff2'); font-style: normal; font-weight: 400 700; font-display: block; }
    @font-face { font-family: 'JetBrains Mono'; src: url('${staticFile('fonts/jetbrains-mono-latin.woff2')}') format('woff2'); font-style: normal; font-weight: 400 700; font-display: block; }
  `}</style>
);

const Shield: React.FC<{ size?: number }> = ({ size = 42 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
    <path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
    <path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
  </svg>
);

const Label: React.FC<{ children: React.ReactNode; color?: string }> = ({ children, color = '#526985' }) => (
  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 14, fontWeight: 600, letterSpacing: 1.1, color, textTransform: 'uppercase' }}>{children}</div>
);

const TitleText: React.FC<{ children: React.ReactNode; size?: number; color?: string }> = ({ children, size = 54, color = '#1a2332' }) => (
  <div style={{ fontFamily: 'DM Sans, Arial, sans-serif', fontSize: size, lineHeight: 1.05, letterSpacing: -1.8, fontWeight: 600, color }}>{children}</div>
);

export const Intro: React.FC = () => {
  const f = useCurrentFrame();
  const p = interpolate(f, [8, 35], [0, 1], { ...clamp, easing: ease });
  const p2 = interpolate(f, [28, 55], [0, 1], { ...clamp, easing: ease });
  const alpha = interpolate(f, [82, 100], [1, 0], clamp);
  return (
    <AbsoluteFill style={{ background: '#f0f4f8', justifyContent: 'center', padding: '0 170px', opacity: alpha }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, color: '#0d1b3e', marginBottom: 64 }}>
        <Shield size={46} />
        <span style={{ font: '700 25px DM Sans, Arial, sans-serif', letterSpacing: -0.5 }}>DeepIntel</span>
      </div>
      <div style={{ overflow: 'hidden', marginBottom: 20 }}>
        <div style={{ opacity: p, transform: `translateY(${(1 - p) * 25}px)` }}><TitleText size={82}>Read the link.</TitleText></div>
      </div>
      <div style={{ overflow: 'hidden' }}>
        <div style={{ opacity: p2, transform: `translateY(${(1 - p2) * 25}px)` }}>
          <TitleText size={82} color="#1a4fa8">See the risk.</TitleText>
        </div>
      </div>
      <div style={{ position: 'absolute', left: 170, bottom: 102, width: 250, height: 3, background: '#1a4fa8', transformOrigin: 'left', transform: `scaleX(${p2})` }} />
    </AbsoluteFill>
  );
};

export const DashboardShot: React.FC = () => {
  const f = useCurrentFrame();
  const local = f;
  const enter = interpolate(local, [0, 25], [0, 1], { ...clamp, easing: ease });
  const exit = interpolate(local, [260, 280], [1, 0], clamp);
  const zoom = interpolate(local, [0, 110, 245], [0.965, 1, 1.015], { ...clamp, easing: ease });
  return (
    <AbsoluteFill style={{ background: '#e7edf4', opacity: enter * exit }}>
      <AbsoluteFill style={{ justifyContent: 'center', alignItems: 'center' }}>
        <div style={{ position: 'absolute', top: 31, left: 120, right: 120, display: 'flex', alignItems: 'center', justifyContent: 'space-between', opacity: enter }}>
          <Label>EXPLAINABLE URL ANALYSIS</Label>
          <span style={{ font: '13px JetBrains Mono, monospace', color: '#8b9caf' }}>01 / DASHBOARD</span>
        </div>
        <div style={{ width: 1700, height: 956, overflow: 'hidden', borderRadius: 14, boxShadow: '0 28px 76px rgba(13,27,62,.19)', border: '1px solid #d0dbe8', transform: `translateY(${(1 - enter) * 28}px) scale(${zoom})` }}>
          <Img src={staticFile('textures/dashboard.png')} style={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover' }} />
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

export const PopupShot: React.FC = () => {
  const f = useCurrentFrame();
  const enter = interpolate(f, [0, 24], [0, 1], { ...clamp, easing: ease });
  const exit = interpolate(f, [172, 192], [1, 0], clamp);
  const zoom = interpolate(f, [0, 80, 165], [0.98, 1.015, 1.02], { ...clamp, easing: ease });
  return (
    <AbsoluteFill style={{ background: '#f0f4f8', opacity: enter * exit }}>
      <div style={{ position: 'absolute', left: 150, top: 0, width: 760, height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', transform: `translateX(${(1 - enter) * -24}px)` }}>
        <Label>IN THE BROWSER</Label>
        <div style={{ marginTop: 24 }}><TitleText size={66}>A clear verdict,</TitleText><TitleText size={66} color="#1a4fa8">where it matters.</TitleText></div>
        <p style={{ font: '500 32px/1.4 DM Sans, Arial, sans-serif', color: '#526985', marginTop: 28, maxWidth: 640 }}>Risk level, confidence, and the signals behind the decision.</p>
        <div style={{ marginTop: 50, width: 64, height: 3, background: '#1a4fa8' }} />
      </div>
      <div style={{ position: 'absolute', left: 1020, top: 82, width: 760, height: 916, borderRadius: 18, background: '#0d1b3e', boxShadow: '0 30px 84px rgba(13,27,62,.22)', overflow: 'hidden', transform: `translateY(${(1 - enter) * 30}px) scale(${zoom})` }}>
        <Img src={staticFile('textures/extension.png')} style={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'top' }} />
      </div>
      <span style={{ position: 'absolute', right: 154, bottom: 35, font: '12px JetBrains Mono, monospace', color: '#758aa2' }}>02 / EXTENSION</span>
    </AbsoluteFill>
  );
};

export const WarningShot: React.FC = () => {
  const f = useCurrentFrame();
  const enter = interpolate(f, [0, 24], [0, 1], { ...clamp, easing: ease });
  const exit = interpolate(f, [118, 138], [1, 0], clamp);
  return (
    <AbsoluteFill style={{ background: '#eaf0f6', opacity: enter * exit, justifyContent: 'center', alignItems: 'center' }}>
      <div style={{ position: 'absolute', left: 160, top: 58, right: 160, display: 'flex', justifyContent: 'space-between' }}>
        <Label>ONION URL PROTECTION</Label>
        <span style={{ font: '13px JetBrains Mono, monospace', color: '#8b9caf' }}>03 / WARNING</span>
      </div>
      <div style={{ position: 'absolute', left: 155, top: 386, width: 490, transform: `translateX(${(1 - enter) * -20}px)` }}>
        <TitleText size={54}>Some links</TitleText>
        <TitleText size={54} color="#c0392b">need a pause.</TitleText>
        <p style={{ font: '500 32px/1.4 DM Sans, Arial, sans-serif', color: '#526985', marginTop: 26 }}>Onion addresses stay outside the analysis API.</p>
      </div>
      <div style={{ position: 'absolute', left: 690, top: 202, width: 1078, height: 676, borderRadius: 16, overflow: 'hidden', boxShadow: '0 28px 74px rgba(13,27,62,.16)', transform: `translateY(${(1 - enter) * 25}px)` }}>
        <Img src={staticFile('textures/warning.png')} style={{ display: 'block', width: '100%', height: '100%', objectFit: 'contain' }} />
      </div>
    </AbsoluteFill>
  );
};

export const Outro: React.FC = () => {
  const f = useCurrentFrame();
  const p = interpolate(f, [0, 22], [0, 1], { ...clamp, easing: ease });
  return (
    <AbsoluteFill style={{ background: '#0d1b3e', opacity: p, justifyContent: 'center', alignItems: 'center', color: '#fff' }}>
      <div style={{ textAlign: 'center', transform: `translateY(${(1 - p) * 18}px)` }}>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 15, marginBottom: 54 }}>
          <Shield size={50} />
          <span style={{ font: '700 30px DM Sans, Arial, sans-serif', letterSpacing: -0.7 }}>DeepIntel</span>
        </div>
        <div style={{ font: '600 58px/1.15 DM Sans, Arial, sans-serif', letterSpacing: -1.6 }}>Know the URL</div>
        <div style={{ font: '600 58px/1.15 DM Sans, Arial, sans-serif', letterSpacing: -1.6, color: '#a8c5e8' }}>before you trust it.</div>
        <div style={{ font: '34px JetBrains Mono, monospace', color: '#a8c5e8', marginTop: 62 }}>github.com/Vishwa-Koparkar/deepintel</div>
      </div>
    </AbsoluteFill>
  );
};

export const DeepIntelPromo: React.FC = () => (
  <AbsoluteFill style={{ fontFamily: 'DM Sans, Arial, sans-serif', background: '#f0f4f8' }}>
    <ProductFonts />
    {SHOTS.map((s) => {
      const component = s.id === 'open' ? <Intro />
        : s.id === 'dashboard' ? <DashboardShot />
          : s.id === 'popup' ? <PopupShot />
            : s.id === 'warning' ? <WarningShot /> : <Outro />;
      return <Sequence key={s.id} from={s.from} durationInFrames={s.duration}>{component}</Sequence>;
    })}
  </AbsoluteFill>
);

export const RemotionRoot: React.FC = () => (
  <>
    <Composition id="DeepIntelPromo" component={DeepIntelPromo} durationInFrames={TOTAL} fps={FPS} width={WIDTH} height={HEIGHT} />
  </>
);
