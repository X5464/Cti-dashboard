/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      // CYBER THEME COLORS
      colors: {
        'cyber-blue': '#3b82f6',
        'cyber-purple': '#8b5cf6',
        'cyber-green': '#10b981',
        'surface': '#1f2937',
        'border': '#374151',
      },
      
      // RESPONSIVE TYPOGRAPHY
      fontFamily: {
        'inter': ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      
      // CUSTOM SHADOWS FOR THREAT LEVELS
      boxShadow: {
        'cyber': '0 0 30px rgba(59, 130, 246, 0.4), 0 0 60px rgba(59, 130, 246, 0.2)',
        'threat': '0 0 20px rgba(239, 68, 68, 0.4), 0 0 40px rgba(239, 68, 68, 0.1)',
        'safe': '0 0 20px rgba(34, 197), 0 0 40px rgba(34, 197, 94, 0.1)',
        'warning': '0 0 20px rgba(251, 191, 36, 0.4), 0 0 40px rgba(251, 191, 36, 0.1)',
      },
      
      // HIGH-PERFORMANCE ANIMATIONS
      animation: {
        'spin-slow': 'spin 2s linear infinite',
        'spin-fast': 'spin 1s linear infinite',
        'pulse-cyber': 'pulse-cyber 2s ease-in-out infinite',
        'shimmer': 'shimmer 2s infinite',
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      
      // CUSTOM KEYFRAMES
      keyframes: {
        'pulse-cyber': {
          '0%, 100%': { 
            opacity: '1',
            boxShadow: '0 0 20px rgba(59, 130, 246, 0.4)'
          },
          '50%': { 
            opacity: '0.7',
            boxShadow: '0 0 40px rgba(59, 130, 246, 0.8)'
          },
        },
        'shimmer': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'fadeIn': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'slideUp': {
          '0%': { transform: 'translateY(100%)' },
          '100%': { transform: 'translateY(0)' },
        },
      },
      
      // RESPONSIVE BREAKPOINTS (Enhanced)
      screens: {
        'xs': '475px',      // Extra small devices
        'sm': '640px',      // Small devices (landscape phones)
        'md': '768px',      // Medium devices (tablets)
        'lg': '1024px',     // Large devices (desktops)
        'xl': '1280px',     // Extra large devices
        '2xl': '1536px',    // 2X large devices
        '3xl': '1600px',    // Ultra wide displays
        
        // Custom breakpoints for specific use cases
        'mobile': {'max': '767px'},      // Mobile-only styles
        'tablet': {'min': '768px', 'max': '1023px'}, // Tablet-only styles
        'desktop': {'min': '1024px'},    // Desktop and up
      },
      
      // SPACING UTILITIES (Enhanced)
      spacing: {
        '18': '4.5rem',     // 72px
        '22': '5.5rem',     // 88px
        '88': '22rem',      // 352px
        '128': '32rem',     // 512px
        '144': '36rem',     // 576px
      },
      
      // MINIMUM SIZES FOR TOUCH TARGETS
      minHeight: {
        'touch': '44px',    // iOS/Android minimum touch target
        'touch-lg': '48px', // Larger touch target for better UX
        'screen-1/2': '50vh',
        'screen-3/4': '75vh',
      },
      
      minWidth: {
        'touch': '44px',    // iOS/Android minimum touch target
        'touch-lg': '48px', // Larger touch target
        '0': '0',
        '1/4': '25%',
        '1/2': '50%',
        '3/4': '75%',
        'full': '100%',
      },
      
      // MAXIMUM WIDTHS (Responsive containers)
      maxWidth: {
        'xs': '20rem',      // 320px
        'sm': '24rem',      // 384px
        'md': '28rem',      // 448px
        'lg': '32rem',      // 512px
        'xl': '36rem',      // 576px
        '2xl': '42rem',     // 672px
        '3xl': '48rem',     // 768px
        '4xl': '56rem',     // 896px
        '5xl': '64rem',     // 1024px
        '6xl': '72rem',     // 1152px
        '7xl': '80rem',     // 1280px
        'none': 'none',
        'full': '100%',
        'screen-sm': '640px',
        'screen-md': '768px',
        'screen-lg': '1024px',
        'screen-xl': '1280px',
        'screen-2xl': '1536px',
      },
      
      // Z-INDEX SCALE
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
      
      // BACKDROP BLUR UTILITIES
      backdropBlur: {
        'xs': '2px',
        'sm': '4px',
        'md': '8px',
        'lg': '12px',
        'xl': '16px',
        '2xl': '24px',
        '3xl': '40px',
      },
      
      // CUSTOM BORDER RADIUS
      borderRadius: {
        '4xl': '2rem',      // 32px
        '5xl': '2.5rem',    // 40px
        '6xl': '3rem',      // 48px
      },
      
      // GRADIENT STOPS
      gradientColorStops: {
        'cyber-blue': '#3b82f6',
        'cyber-purple': '#8b5cf6',
        'cyber-green': '#10b981',
      },
      
      // CUSTOM FONT SIZES (Responsive typography)
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }],      // 12px
        'sm': ['0.875rem', { lineHeight: '1.25rem' }],  // 14px
        'base': ['1rem', { lineHeight: '1.5rem' }],     // 16px
        'lg': ['1.125rem', { lineHeight: '1.75rem' }],  // 18px
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],   // 20px
        '2xl': ['1.5rem', { lineHeight: '2rem' }],      // 24px
        '3xl': ['1.875rem', { lineHeight: '2.25rem' }], // 30px
        '4xl': ['2.25rem', { lineHeight: '2.5rem' }],   // 36px
        '5xl': ['3rem', { lineHeight: '1' }],           // 48px
        '6xl': ['3.75rem', { lineHeight: '1' }],        // 60px
        '7xl': ['4.5rem', { lineHeight: '1' }],         // 72px
        '8xl': ['6rem', { lineHeight: '1' }],           // 96px
        '9xl': ['8rem', { lineHeight: '1' }],           // 128px
        
        // Responsive font sizes
        'responsive-xs': ['0.75rem', { lineHeight: '1rem' }],
        'responsive-sm': ['0.875rem', { lineHeight: '1.25rem' }],
        'responsive-base': ['1rem', { lineHeight: '1.5rem' }],
        'responsive-lg': ['1.125rem', { lineHeight: '1.75rem' }],
      },
      
      // TRANSITIONS & TIMING
      transitionDuration: {
        '250': '250ms',
        '350': '350ms',
        '400': '400ms',
        '600': '600ms',
        '800': '800ms',
        '1200': '1200ms',
      },
      
      transitionTimingFunction: {
        'in-expo': 'cubic-bezier(0.95, 0.05, 0.795, 0.035)',
        'out-expo': 'cubic-bezier(0.19, 1, 0.22, 1)',
        'bounce-in': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
      },
    },
  },
  
  // PLUGINS FOR ENHANCED FUNCTIONALITY
  plugins: [
    // Custom utilities plugin
    function({ addUtilities, addComponents, theme }) {
      // Touch target utilities
      const touchUtilities = {
        '.touch-target': {
          minHeight: '44px',
          minWidth: '44px',
          cursor: 'pointer',
        },
        '.touch-target-lg': {
          minHeight: '48px',
          minWidth: '48px',
          cursor: 'pointer',
        },
      }
      
      // Safe area utilities for mobile devices
      const safeAreaUtilities = {
        '.safe-area-top': {
          paddingTop: 'max(env(safe-area-inset-top), 1rem)',
        },
        '.safe-area-bottom': {
          paddingBottom: 'max(env(safe-area-inset-bottom), 1rem)',
        },
        '.safe-area-left': {
          paddingLeft: 'max(env(safe-area-inset-left), 0.75rem)',
        },
        '.safe-area-right': {
          paddingRight: 'max(env(safe-area-inset-right), 0.75rem)',
        },
        '.safe-area-inset': {
          paddingTop: 'max(env(safe-area-inset-top), 1rem)',
          paddingBottom: 'max(env(safe-area-inset-bottom), 1rem)',
          paddingLeft: 'max(env(safe-area-inset-left), 0.75rem)',
          paddingRight: 'max(env(safe-area-inset-right), 0.75rem)',
        },
      }
      
      // GPU acceleration utilities
      const performanceUtilities = {
        '.gpu-accelerate': {
          transform: 'translateZ(0)',
          backfaceVisibility: 'hidden',
        },
        '.smooth-scroll': {
          '-webkit-overflow-scrolling': 'touch',
          scrollBehavior: 'smooth',
        },
      }
      
      // Responsive grid utilities
      const gridUtilities = {
        '.responsive-grid': {
          display: 'grid',
          gridTemplateColumns: '1fr',
          gap: '0.75rem',
          '@screen sm': {
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '1rem',
          },
          '@screen md': {
            gap: '1.25rem',
          },
          '@screen lg': {
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '1.5rem',
          },
          '@screen xl': {
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '2rem',
          },
        },
      }
      
      // Cyber theme components
      const cyberComponents = {
        '.btn-cyber': {
          background: `linear-gradient(135deg, ${theme('colors.cyber-blue')}, ${theme('colors.cyber-purple')})`,
          color: 'white',
          padding: `${theme('spacing.3')} ${theme('spacing.6')}`,
          borderRadius: theme('borderRadius.xl'),
          fontWeight: theme('fontWeight.semibold'),
          transition: 'all 0.3s ease',
          minHeight: '44px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          '&:hover': {
            boxShadow: theme('boxShadow.cyber'),
            transform: 'translateY(-2px)',
          },
          '&:disabled': {
            opacity: '0.5',
            cursor: 'not-allowed',
            '&:hover': {
              transform: 'none',
              boxShadow: 'none',
            },
          },
        },
        
        '.card-cyber': {
          background: 'rgba(31, 41, 55, 0.3)',
          backdropFilter: 'blur(8px)',
          border: `1px solid ${theme('colors.border')}`,
          borderRadius: theme('borderRadius.xl'),
          padding: theme('spacing.6'),
          transition: 'all 0.3s ease',
          '&:hover': {
            borderColor: theme('colors.cyber-blue'),
            boxShadow: `0 0 20px ${theme('colors.cyber-blue')}20`,
          },
        },
        
        '.input-cyber': {
          background: 'rgba(255, 255, 255, 0.05)',
          border: `1px solid ${theme('colors.border')}`,
          borderRadius: theme('borderRadius.xl'),
          padding: `${theme('spacing.3')} ${theme('spacing.4')}`,
          color: 'white',
          backdropFilter: 'blur(4px)',
          minHeight: '44px',
          fontSize: theme('fontSize.base')[0],
          transition: 'all 0.3s ease',
          '&:focus': {
            outline: 'none',
            borderColor: theme('colors.cyber-blue'),
            boxShadow: `0 0 0 2px ${theme('colors.cyber-blue')}40`,
          },
          '&::placeholder': {
            color: 'rgba(156, 163, 175, 0.7)',
          },
        },
      }
      
      // Loading states
      const loadingUtilities = {
        '.loading-shimmer': {
          background: 'linear-gradient(90deg, rgba(255,255,255,0.1) 25%, rgba(255,255,255,0.2) 50%, rgba(255,255,255,0.1) 75%)',
          backgroundSize: '200% 100%',
          animation: 'shimmer 2s infinite',
        },
        '.loading-skeleton': {
          backgroundColor: 'rgba(156, 163, 175, 0.2)',
          borderRadius: theme('borderRadius.md'),
          animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        },
      }
      
      addUtilities({
        ...touchUtilities,
        ...safeAreaUtilities,
        ...performanceUtilities,
        ...gridUtilities,
        ...loadingUtilities,
      })
      
      addComponents(cyberComponents)
    },
    
    // Responsive font size plugin
    function({ addUtilities, theme }) {
      const responsiveFontSizes = {
        '.text-responsive-xs': {
          fontSize: '0.75rem',
          '@screen sm': { fontSize: '0.875rem' },
          '@screen lg': { fontSize: '1rem' },
        },
        '.text-responsive': {
          fontSize: '0.875rem',
          '@screen sm': { fontSize: '1rem' },
          '@screen lg': { fontSize: '1.125rem' },
        },
        '.text-responsive-lg': {
          fontSize: '1rem',
          '@screen sm': { fontSize: '1.125rem' },
          '@screen lg': { fontSize: '1.25rem' },
        },
        '.text-responsive-xl': {
          fontSize: '1.125rem',
          '@screen sm': { fontSize: '1.25rem' },
          '@screen lg': { fontSize: '1.5rem' },
        },
      }
      
      addUtilities(responsiveFontSizes)
    },
    
    // Dark mode improvements
    function({ addVariant }) {
      addVariant('mobile', '@media (max-width: 767px)')
      addVariant('tablet', '@media (min-width: 768px) and (max-width: 1023px)')
      addVariant('desktop', '@media (min-width: 1024px)')
      addVariant('touch', '@media (hover: none)')
      addVariant('no-touch', '@media (hover: hover)')
    },
  ],
  
  // VARIANT CONFIGURATION
  variants: {
    extend: {
      backgroundColor: ['active', 'group-hover'],
      textColor: ['active', 'group-hover'],
      borderColor: ['active', 'group-hover'],
      scale: ['active', 'group-hover'],
      translate: ['active', 'group-hover'],
      opacity: ['disabled'],
      cursor: ['disabled'],
    },
  },
  
  // CORE PLUGINS (Ensure all are enabled)
  corePlugins: {
    // Enable all core plugins for maximum flexibility
    preflight: true,
    container: true,
    accessibility: true,
    alignContent: true,
    alignItems: true,
    alignSelf: true,
    animation: true,
    appearance: true,
    backdropBlur: true,
    backdropBrightness: true,
    backdropContrast: true,
    backdropFilter: true,
    backdropGrayscale: true,
    backdropHueRotate: true,
    backdropInvert: true,
    backdropOpacity: true,
    backdropSaturate: true,
    backdropSepia: true,
    backgroundColor: true,
    backgroundImage: true,
    backgroundOpacity: true,
    backgroundPosition: true,
    backgroundRepeat: true,
    backgroundSize: true,
    borderCollapse: true,
    borderColor: true,
    borderOpacity: true,
    borderRadius: true,
    borderStyle: true,
    borderWidth: true,
    boxShadow: true,
    boxSizing: true,
    cursor: true,
    display: true,
    divideColor: true,
    divideOpacity: true,
    divideStyle: true,
    divideWidth: true,
    fill: true,
    flex: true,
    flexDirection: true,
    flexGrow: true,
    flexShrink: true,
    flexWrap: true,
    float: true,
    fontFamily: true,
    fontSize: true,
    fontSmoothing: true,
    fontStyle: true,
    fontVariantNumeric: true,
    fontWeight: true,
    gap: true,
    gradientColorStops: true,
    gridAutoColumns: true,
    gridAutoFlow: true,
    gridAutoRows: true,
    gridColumn: true,
    gridColumnEnd: true,
    gridColumnStart: true,
    gridRow: true,
    gridRowEnd: true,
    gridRowStart: true,
    gridTemplateColumns: true,
    gridTemplateRows: true,
    height: true,
    inset: true,
    justifyContent: true,
    justifyItems: true,
    justifySelf: true,
    letterSpacing: true,
    lineHeight: true,
    listStylePosition: true,
    listStyleType: true,
    margin: true,
    maxHeight: true,
    maxWidth: true,
    minHeight: true,
    minWidth: true,
    mixBlendMode: true,
    objectFit: true,
    objectPosition: true,
    opacity: true,
    order: true,
    outline: true,
    overflow: true,
    overscrollBehavior: true,
    padding: true,
    placeContent: true,
    placeItems: true,
    placeSelf: true,
    placeholderColor: true,
    placeholderOpacity: true,
    pointerEvents: true,
    position: true,
    resize: true,
    ringColor: true,
    ringOffsetColor: true,
    ringOffsetWidth: true,
    ringOpacity: true,
    ringWidth: true,
    rotate: true,
    scale: true,
    skew: true,
    space: true,
    stroke: true,
    strokeWidth: true,
    tableLayout: true,
    textAlign: true,
    textColor: true,
    textDecoration: true,
    textDecorationColor: true,
    textDecorationStyle: true,
    textDecorationThickness: true,
    textIndent: true,
    textOpacity: true,
    textOverflow: true,
    textTransform: true,
    textUnderlineOffset: true,
    transform: true,
    transformOrigin: true,
    transitionDelay: true,
    transitionDuration: true,
    transitionProperty: true,
    transitionTimingFunction: true,
    translate: true,
    userSelect: true,
    verticalAlign: true,
    visibility: true,
    whitespace: true,
    width: true,
    wordBreak: true,
    zIndex: true,
  },
}
