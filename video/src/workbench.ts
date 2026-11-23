import { DashboardShot, DeepIntelPromo, FPS, HEIGHT, Intro, Outro, PopupShot, SHOTS, TOTAL, WIDTH, WarningShot } from './Main';

const components = {
  open: Intro,
  dashboard: DashboardShot,
  popup: PopupShot,
  warning: WarningShot,
  close: Outro,
};

export const WORKBENCH = {
  name: 'DeepIntel Product Promo',
  fps: FPS,
  width: WIDTH,
  height: HEIGHT,
  total: TOTAL,
  background: '#f0f4f8',
  shots: SHOTS.map((shot) => ({ ...shot, component: components[shot.id] })),
  original: DeepIntelPromo,
};
