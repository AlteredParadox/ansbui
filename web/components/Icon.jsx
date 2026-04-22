// Small icon set — sharp, line-based, 1.5px stroke, 16px viewBox
// Usage: <Icon name="inventory" size={16} />
const Icon = ({ name, size = 16, className = '', strokeWidth = 1.5 }) => {
  const props = {
    width: size,
    height: size,
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    className
  };
  const P = (d) => <path d={d} />;
  switch (name) {
    case 'dashboard':
      return <svg {...props}><rect x="2" y="2" width="5" height="6" rx="1"/><rect x="2" y="10" width="5" height="4" rx="1"/><rect x="9" y="2" width="5" height="4" rx="1"/><rect x="9" y="8" width="5" height="6" rx="1"/></svg>;
    case 'inventory':
      return <svg {...props}><path d="M2 4h12M2 8h12M2 12h12"/><circle cx="5" cy="4" r="1" fill="currentColor"/><circle cx="9" cy="8" r="1" fill="currentColor"/><circle cx="6" cy="12" r="1" fill="currentColor"/></svg>;
    case 'playbooks':
      return <svg {...props}><path d="M3 2.5A1.5 1.5 0 0 1 4.5 1H13v12.5a1.5 1.5 0 0 1-1.5 1.5H4.5A1.5 1.5 0 0 1 3 13.5Z"/><path d="M6 5h5M6 8h5M6 11h3"/></svg>;
    case 'terminal':
      return <svg {...props}><rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M4.5 6l2 2-2 2M8 10.5h3.5"/></svg>;
    case 'history':
      return <svg {...props}><path d="M8 3.5a4.5 4.5 0 1 1-4.44 3.75"/><path d="M3 2v3h3"/><path d="M8 5.5V8l1.75 1.5"/></svg>;
    case 'vault':
      return <svg {...props}><rect x="2.5" y="6.5" width="11" height="7" rx="1.5"/><path d="M5 6.5V4.5a3 3 0 0 1 6 0v2"/><circle cx="8" cy="10" r="0.9" fill="currentColor"/></svg>;
    case 'settings':
      return <svg {...props}><circle cx="8" cy="8" r="2"/><path d="M8 1.5v1.8M8 12.7v1.8M3.2 3.2l1.3 1.3M11.5 11.5l1.3 1.3M1.5 8h1.8M12.7 8h1.8M3.2 12.8l1.3-1.3M11.5 4.5l1.3-1.3"/></svg>;
    case 'search':
      return <svg {...props}><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/></svg>;
    case 'plus':
      return <svg {...props}><path d="M8 3v10M3 8h10"/></svg>;
    case 'play':
      return <svg {...props}><path d="M4.5 3l8 5-8 5z" fill="currentColor" stroke="none"/></svg>;
    case 'chevron-right':
      return <svg {...props}><path d="M6 3l5 5-5 5"/></svg>;
    case 'chevron-down':
      return <svg {...props}><path d="M3 6l5 5 5-5"/></svg>;
    case 'chevron-up':
      return <svg {...props}><path d="M3 10l5-5 5 5"/></svg>;
    case 'check':
      return <svg {...props}><path d="M3 8.5 6.5 12 13 4.5"/></svg>;
    case 'x':
      return <svg {...props}><path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/></svg>;
    case 'filter':
      return <svg {...props}><path d="M2 3h12l-4.5 5.5V13l-3 1.5V8.5z"/></svg>;
    case 'tag':
      return <svg {...props}><path d="M2.5 7.5 7.5 2.5H13v5.5l-5 5z"/><circle cx="10.5" cy="5.5" r="0.8" fill="currentColor"/></svg>;
    case 'globe':
      return <svg {...props}><circle cx="8" cy="8" r="5.5"/><path d="M2.5 8h11M8 2.5c1.75 2 1.75 9 0 11M8 2.5c-1.75 2-1.75 9 0 11"/></svg>;
    case 'server':
      return <svg {...props}><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/><circle cx="5" cy="5" r="0.6" fill="currentColor"/><circle cx="5" cy="11" r="0.6" fill="currentColor"/></svg>;
    case 'group':
      return <svg {...props}><circle cx="5" cy="6" r="2"/><circle cx="11" cy="6" r="2"/><path d="M2 13c0-1.66 1.34-3 3-3s3 1.34 3 3M8 13c0-1.66 1.34-3 3-3s3 1.34 3 3"/></svg>;
    case 'graph':
      return <svg {...props}><circle cx="4" cy="4" r="1.5"/><circle cx="12" cy="4" r="1.5"/><circle cx="8" cy="12" r="1.5"/><path d="M5 5l2 6M11 5l-2 6"/></svg>;
    case 'map':
      return <svg {...props}><path d="M2 4v10l4-1.5 4 1.5 4-1.5V3l-4 1.5L6 3Z"/><path d="M6 3v10M10 4.5v10"/></svg>;
    case 'code':
      return <svg {...props}><path d="M6 4.5 2.5 8 6 11.5M10 4.5 13.5 8 10 11.5"/></svg>;
    case 'refresh':
      return <svg {...props}><path d="M13 3v3h-3"/><path d="M3 8a5 5 0 0 1 9.2-2.7L13 6"/><path d="M3 13v-3h3"/><path d="M13 8a5 5 0 0 1-9.2 2.7L3 10"/></svg>;
    case 'download':
      return <svg {...props}><path d="M8 2v8m0 0 3-3m-3 3L5 7M3 12.5v1A1.5 1.5 0 0 0 4.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-1"/></svg>;
    case 'sun':
      return <svg {...props}><circle cx="8" cy="8" r="2.8"/><path d="M8 1.5v1.4M8 13.1v1.4M14.5 8h-1.4M2.9 8H1.5M12.6 3.4l-1 1M4.4 11.6l-1 1M12.6 12.6l-1-1M4.4 4.4l-1-1"/></svg>;
    case 'moon':
      return <svg {...props}><path d="M13 9.2A5.5 5.5 0 0 1 6.8 3a5.5 5.5 0 1 0 6.2 6.2Z"/></svg>;
    case 'layout':
      return <svg {...props}><rect x="2" y="2" width="12" height="12" rx="1.5"/><path d="M6 2v12M2 6h4"/></svg>;
    case 'user':
      return <svg {...props}><circle cx="8" cy="5.5" r="2.5"/><path d="M3 13.5c0-2.5 2.25-4 5-4s5 1.5 5 4"/></svg>;
    case 'key':
      return <svg {...props}><circle cx="5" cy="8" r="2.5"/><path d="M7.2 7l5.3-5.3M11 3.5l1.5 1.5M9 5.5 10.5 7"/></svg>;
    case 'cert':
      return <svg {...props}><rect x="2" y="2.5" width="12" height="9" rx="1"/><path d="M5 14l3-1 3 1v-3.5"/><path d="M5.5 6h5M5.5 8.5h3"/></svg>;
    case 'more':
      return <svg {...props}><circle cx="3.5" cy="8" r="0.8" fill="currentColor"/><circle cx="8" cy="8" r="0.8" fill="currentColor"/><circle cx="12.5" cy="8" r="0.8" fill="currentColor"/></svg>;
    case 'star':
      return <svg {...props}><path d="M8 2l1.8 3.8L14 6.4l-3 3 .7 4.2L8 11.8 4.3 13.6 5 9.4l-3-3 4.2-.6z"/></svg>;
    case 'clock':
      return <svg {...props}><circle cx="8" cy="8" r="5.5"/><path d="M8 5v3l2 1.5"/></svg>;
    case 'bolt':
      return <svg {...props}><path d="M9 2 4 9h3.5l-1 5 5-7h-3.5z"/></svg>;
    case 'hash':
      return <svg {...props}><path d="M6 2 4.5 14M11.5 2 10 14M2.5 6h11M2 10h11"/></svg>;
    default:
      return <svg {...props}><rect x="2" y="2" width="12" height="12" rx="2"/></svg>;
  }
};

window.Icon = Icon;
