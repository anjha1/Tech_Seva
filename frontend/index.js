import React from 'react';
import ReactDOM from 'react-dom/client';
import LocationSearchInput from './LocationSearchInput';

function renderLocationSearchInput(element, onLocationSelect, initialLocation = '') {
  if (!element) {
    console.error('Target element not found for rendering LocationSearchInput.');
    return;
  }
  let root = ReactDOM.createRoot(element);
  root.render(
    <React.StrictMode>
      <LocationSearchInput
        onLocationSelect={onLocationSelect}
        initialLocation={initialLocation}
      />
    </React.StrictMode>
  );
  return root;
}
window.renderLocationSearchInput = renderLocationSearchInput;
