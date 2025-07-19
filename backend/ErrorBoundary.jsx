import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-dark-bg text-white flex items-center justify-center">
          <div className="max-w-2xl mx-auto p-8 text-center">
            <div className="text-6xl mb-4">🚨</div>
            <h1 className="text-2xl font-bold mb-4 text-red-400">Something went wrong</h1>
            <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 mb-6 text-left">
              <h3 className="font-semibold mb-2">Error Details:</h3>
              <pre className="text-sm text-red-300 overflow-x-auto">
                {this.state.error && this.state.error.toString()}
              </pre>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="bg-cyber-blue text-dark-bg px-6 py-3 rounded-lg font-semibold hover:bg-blue-400 transition-colors"
            >
              🔄 Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
