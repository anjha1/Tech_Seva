import React, { useState, useEffect, useRef, useCallback } from 'react';

// Pre-defined static list of locations for demonstration
const MOCK_LOCATIONS = [
  "Patna, Bihar, India",
  "Patna Junction, Fraser Road Area, Patna, Bihar, India",
  "Patliputra Station, Patliputra Station Road, Jagat Vihar Colony, Rukanpura, Patna, Bihar, India",
  "Patna Zoo, Bailey Road, Sheikhpura, Patna, Bihar, India",
  "Jay Prakash Narayan International Airport, Shaheed Pir Ali Khan Marg, Sheikhpura, Patna, Bihar, India",
  "Darbhanga, Bihar, India",
  "Dariyapur, Bihar, India",
  "Darjeeling, West Bengal, India",
  "Darbhanga Airport, Aerodrome Darbhanga, Ranipur, Darbhanga, Bihar, India",
  "Darihara, Bihar, India",
  "Madhubani, Bihar, India",
  "Madhopur, Bihar, India",
  "Madhurapur, Bihar, India",
  "Madhepura, Bihar, India",
  "Madurai, Tamil Nadu, India",
  "Bangalore, Karnataka, India",
  "Bengaluru City Junction Railway Station, Majestic, Bengaluru, Karnataka, India",
  "Indira Nagar, Bengaluru, Karnataka, India",
  "Kempegowda International Airport Bengaluru, Devanahalli, Bengaluru, Karnataka, India",
  "Mumbai, Maharashtra, India",
  "Chhatrapati Shivaji Maharaj International Airport, Mumbai, Maharashtra, India",
  "Marine Drive, Mumbai, Maharashtra, India",
  "New Delhi, Delhi, India",
  "Connaught Place, New Delhi, Delhi, India",
  "New Delhi Railway Station, Paharganj, New Delhi, Delhi, India",
  "Hyderabad, Telangana, India",
  "Secunderabad Railway Station, Hyderabad, Telangana, India",
  "Chennai, Tamil Nadu, India",
  "Chennai Central Railway Station, Park Town, Chennai, Tamil Nadu, India",
  "Kolkata, West Bengal, India",
  "Howrah Junction Railway Station, Howrah, West Bengal, India",
  "Jaipur, Rajasthan, India",
  "Amer Fort, Jaipur, Rajasthan, India",
  "Ahmedabad, Gujarat, India",
  "Gandhinagar, Gujarat, India",
  "Pune, Maharashtra, India",
  "Lucknow, Uttar Pradesh, India",
  "Kanpur, Uttar Pradesh, India",
  "Varanasi, Uttar Pradesh, India",
  "Agra, Uttar Pradesh, India",
  "Thiruvananthapuram, Kerala, India",
  "Kochi, Kerala, India",
  "Coimbatore, Tamil Nadu, India",
  "Madurai, Tamil Nadu, India",
  "Bhopal, Madhya Pradesh, India",
  "Indore, Madhya Pradesh, India",
  "Chandigarh, Punjab, India",
  "Amritsar, Punjab, India",
  "Guwahati, Assam, India",
  "Bhubaneswar, Odisha, India",
  "Ranchi, Jharkhand, India",
  "Nagpur, Maharashtra, India",
  "Nashik, Maharashtra, India",
  "Surat, Gujarat, India",
  "Vadodara, Gujarat, India",
  "Visakhapatnam, Andhra Pradesh, India",
  "Vijayawada, Andhra Pradesh, India",
  "Mysore, Karnataka, India",
  "Mangalore, Karnataka, India",
  "Goa, India",
  "Panaji, Goa, India",
  "Shimla, Himachal Pradesh, India",
  "Manali, Himachal Pradesh, India",
  "Srinagar, Jammu and Kashmir, India",
  "Leh, Ladakh, India",
  "Port Blair, Andaman and Nicobar Islands, India",
  "Puducherry, Puducherry, India"
];


function LocationSearchInput({ onLocationSelect, initialLocation = '' }) {
  const [searchQuery, setSearchQuery] = useState(initialLocation);
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const [gpsLoading, setGpsLoading] = useState(false);
  const [gpsError, setGpsError] = useState('');

  const inputRef = useRef(null);
  const suggestionsRef = useRef(null);
  const debounceTimeoutRef = useRef(null);

  // Function to filter static mock locations
  // This function filters the MOCK_LOCATIONS based on the query.
  // If no matches are found, it returns an empty array.
  // IMPORTANT: This function does NOT modify the `searchQuery` state (the text in the input field).
  const filterSuggestions = useCallback((query) => {
    // Suggestions are filtered only when query is 2 or more characters.
    // This reduces irrelevant suggestions for single letters.
    if (query.length < 2) {
      return [];
    }
    const lowerCaseQuery = query.toLowerCase();
    const filtered = MOCK_LOCATIONS.filter(location =>
      location.toLowerCase().includes(lowerCaseQuery)
    );
    // Sort to prioritize exact starts, then general inclusion (simple relevance)
    filtered.sort((a, b) => {
      const aLower = a.toLowerCase();
      const bLower = b.toLowerCase();
      const queryLower = lowerCaseQuery;

      const aStartsWith = aLower.startsWith(queryLower);
      const bStartsWith = bLower.startsWith(queryLower);

      if (aStartsWith && !bStartsWith) return -1;
      if (!aStartsWith && bStartsWith) return 1;
      return aLower.localeCompare(bLower); // Alphabetical for tie-break
    });

    return filtered.slice(0, 5); // Return top 5
  }, []);

  // Effect for handling search query changes (debounced for performance)
  useEffect(() => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    
    if (searchQuery.length > 0) {
        setLoading(true); // Indicate loading for local filtering, though fast
        debounceTimeoutRef.current = setTimeout(() => {
            const newSuggestions = filterSuggestions(searchQuery);
            setSuggestions(newSuggestions);
            // Only show suggestions if there are actual results OR query is very short (to show 'type more' msg)
            setShowSuggestions(newSuggestions.length > 0 || searchQuery.length < 2); 
            setLoading(false);
        }, 50); // Very short debounce for near-instant response
    } else {
        setSuggestions([]);
        setShowSuggestions(false); // Hide if query is completely empty
        setLoading(false);
    }

    return () => {
      clearTimeout(debounceTimeoutRef.current);
    };
  }, [searchQuery, filterSuggestions]);

  // Handle input change
  const handleChange = (e) => {
    const value = e.target.value;
    setSearchQuery(value); // This ensures the typed value always stays in the input
    // Always show suggestions dropdown as user types, even if empty, to show guidance.
    setShowSuggestions(true); 
    setSelectedSuggestionIndex(-1); // Reset highlight on new input

    // Pass the raw typed value back to the parent form for intermediate updates
    onLocationSelect({
      formattedAddress: value, // Pass raw value first
      placeId: null,
      latitude: null,
      longitude: null
    });
  };

  // Clear input and hide suggestions
  const handleClear = () => {
    setSearchQuery('');
    setSuggestions([]);
    setShowSuggestions(false);
    setSelectedSuggestionIndex(-1);
    setGpsError(''); // Clear any GPS errors
    onLocationSelect({
      formattedAddress: '',
      placeId: null,
      latitude: null,
      longitude: null
    }); // Clear location in parent
    inputRef.current.focus();
  };

  // Handle suggestion click or Enter press on a selected suggestion
  const handleSelectSuggestion = async (suggestion) => {
    const formattedAddress = suggestion; // MOCK_LOCATIONS directly provides formatted address
    const placeId = null; // No place_id from mock data for mock data

    console.log("Selected suggestion (handleSelectSuggestion):", formattedAddress); // Debug log
    setSearchQuery(formattedAddress); // Update React state for input display
    setSuggestions([]); // Clear suggestions
    setShowSuggestions(false); // Hide the dropdown

    // Call the parent callback with the selected location details
    onLocationSelect({
      formattedAddress: formattedAddress,
      placeId: placeId,
      latitude: null,
      longitude: null
    });
    inputRef.current.blur(); // Remove focus after selection
  };

  // Handle keyboard navigation for suggestions
  const handleKeyDown = (e) => {
    if (showSuggestions && suggestions.length > 0) { // Only handle arrows if suggestions are shown and available
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedSuggestionIndex((prevIndex) =>
          prevIndex < suggestions.length - 1 ? prevIndex + 1 : 0
        );
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedSuggestionIndex((prevIndex) =>
          prevIndex > 0 ? prevIndex - 1 : suggestions.length - 1
        );
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (selectedSuggestionIndex !== -1 && suggestions[selectedSuggestionIndex]) {
          console.log("Enter pressed: Selecting highlighted suggestion:", suggestions[selectedSuggestionIndex]); // Debug log
          handleSelectSuggestion(suggestions[selectedSuggestionIndex]);
        } else if (searchQuery.trim() !== '' && suggestions.length > 0) {
          // If Enter is pressed, no item is highlighted, but suggestions exist, select the first.
          console.log("Enter pressed: Selecting first suggestion (no highlight):", suggestions[0]); // Debug log
          handleSelectSuggestion(suggestions[0]);
        } else {
            // If Enter is pressed with no suggestion selected/found, keep the typed text.
            // Explicitly call onLocationSelect with current searchQuery to confirm it.
            console.log("Enter pressed: Confirming typed value as location:", searchQuery); // Debug log
            onLocationSelect({
              formattedAddress: searchQuery,
              placeId: null,
              latitude: null,
              longitude: null
            });
            setShowSuggestions(false);
            setSuggestions([]);
            inputRef.current.blur();
        }
      } else if (e.key === 'Escape') {
        setShowSuggestions(false);
        setSuggestions([]);
        inputRef.current.blur();
      }
    } else if (e.key === 'Escape') { // Allow escape to clear and hide even if no suggestions visible
        setShowSuggestions(false);
        setSuggestions([]);
        inputRef.current.blur();
    } else if (e.key === 'Enter' && searchQuery.trim() !== '') {
      // This handles the case where no suggestions are shown at all (e.g., query.length < 2)
      // but the user presses Enter to confirm their typed input.
      console.log("Enter pressed (no suggestions shown): Confirming typed value as location:", searchQuery); // Debug log
      onLocationSelect({
        formattedAddress: searchQuery,
        placeId: null,
        latitude: null,
        longitude: null
      });
      setShowSuggestions(false);
      setSuggestions([]);
      inputRef.current.blur();
    }
  };

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      // Check if the click occurred outside both the input and the suggestions dropdown
      if (inputRef.current && !inputRef.current.contains(event.target) &&
          suggestionsRef.current && !suggestionsRef.current.contains(event.target)) {
        setShowSuggestions(false);
        setSelectedSuggestionIndex(-1);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Function to format the suggestion text with bold highlighting for matching parts
  const formatSuggestion = (description, query) => {
    if (!query || query.length < 2) { // No highlighting if query is too short or empty
      return <span className="text-gray-800">{description}</span>; // Default color for all text
    }

    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedQuery})`, 'gi'); // Case-insensitive regex
    const parts = description.split(regex);

    return (
      <span>
        {parts.map((part, index) =>
          // If the part matches the regex (i.e., it's one of the split segments that was the query)
          regex.test(part) && query.length > 0 ? (
            <span key={index} className="font-bold text-gray-800">
              {part}
            </span>
          ) : (
            <span key={index} className="text-gray-600"> {/* Use a consistent gray for non-matching parts */}
              {part}
            </span>
          )
        )}
      </span>
    );
  };

  // Handle GPS location request
  const handleUseGpsLocation = async () => {
    setGpsLoading(true);
    setGpsError('');
    setShowSuggestions(false); // Hide suggestions when fetching GPS

    if (!navigator.geolocation) {
      setGpsError('Geolocation is not supported by your browser.');
      setGpsLoading(false);
      return;
    }

    navigator.geolocation.getCurrentPosition(async (position) => {
      try {
        const { latitude, longitude } = position.coords;
        // Make backend call to reverse geocode
        const response = await fetch('/api/reverse-geocode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ latitude, longitude }),
        });
        const data = await response.json();

        if (data.success && data.address) {
          setSearchQuery(data.address);
          onLocationSelect({
            formattedAddress: data.address,
            placeId: null, // No place_id for reverse geocoded simple address
            latitude: latitude,
            longitude: longitude
          });
          setGpsError(''); // Clear any previous errors
        } else {
          setGpsError(data.message || 'Could not find address for your location.');
        }
      } catch (error) {
        console.error('Error during reverse geocoding:', error);
        setGpsError('Network error or server issue fetching location details.');
      } finally {
        setGpsLoading(false);
      }
    }, (error) => {
      console.error('Geolocation error:', error);
      setGpsLoading(false);
      let errorMessage = 'Unable to retrieve your location.';
      switch(error.code) {
        case error.PERMISSION_DENIED:
          errorMessage = 'Location access denied. Please enable it in browser settings.';
          break;
        case error.POSITION_UNAVAILABLE:
          errorMessage = 'Location information is unavailable.';
          break;
        case error.TIMEOUT:
          errorMessage = 'The request to get user location timed out.';
          break;
        default:
          errorMessage = 'An unknown geolocation error occurred.';
          break;
      }
      setGpsError(errorMessage);
    }, {
      enableHighAccuracy: true,
      timeout: 10000,
      maximumAge: 0
    });
  };

  return (
    <div className="relative w-full font-sans">
      {/* Search Input Area */}
      <div className="relative flex items-center bg-white border border-gray-300 rounded-lg shadow-sm transition-all duration-300 ease-in-out focus-within:ring-2 focus-within:ring-blue-300 focus-within:border-blue-500">
        <i className="fas fa-search text-gray-400 ml-4 mr-3"></i>
        <input
          ref={inputRef}
          type="text"
          className="flex-grow py-2.5 px-1 rounded-lg text-lg text-gray-800 placeholder-gray-400 focus:outline-none bg-transparent"
          placeholder="Enter your address"
          value={searchQuery}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onFocus={() => {
            // Show suggestions immediately on focus.
            setShowSuggestions(true); 
            // Re-trigger filtering on focus if query length is >= 2, otherwise clear suggestions for short query msg.
            if (searchQuery.length >= 2) {
                const newSuggestions = filterSuggestions(searchQuery);
                setSuggestions(newSuggestions);
            } else {
                setSuggestions([]); // Clear suggestions if query is too short for results
            }
          }}
        />
        {searchQuery && (
          <button
            onClick={handleClear}
            className="mr-3 text-gray-500 hover:text-gray-700 focus:outline-none"
          >
            <i className="fas fa-times-circle"></i>
          </button>
        )}
      </div>

      {/* Suggestions Dropdown */}
      {showSuggestions && (loading || suggestions.length > 0 || searchQuery.length < 2) && ( 
        <div
          ref={suggestionsRef}
          className="absolute top-full left-0 right-0 mt-1 bg-white rounded-lg shadow-xl overflow-hidden max-h-60 overflow-y-auto z-50
                     border border-gray-200"
        >
          {loading ? (
            <div className="p-3 text-center text-gray-500 text-sm">Filtering suggestions...</div>
          ) : searchQuery.length < 2 ? (
             <div className="p-3 text-center text-gray-500 text-sm">Type at least 2 characters for suggestions.</div>
          ) : suggestions.length === 0 ? ( // Only show "No results" if query is long enough but no matches
            <div className="p-3 text-center text-gray-500 text-sm">No results found.</div>
          ) : (
            <ul>
              {suggestions.map((suggestion, index) => (
                <React.Fragment key={suggestion}>
                  <li
                    className={`cursor-pointer px-4 py-3 text-gray-800 hover:bg-blue-50 transition-colors duration-150
                                ${index === selectedSuggestionIndex ? 'bg-blue-100' : ''}`}
                    onClick={() => handleSelectSuggestion(suggestion)}
                    onMouseEnter={() => setSelectedSuggestionIndex(index)}
                    onMouseLeave={() => setSelectedSuggestionIndex(-1)}
                  >
                    {formatSuggestion(suggestion, searchQuery)}
                  </li>
                </React.Fragment>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* GPS Button and Status */}
      <div className="flex items-center justify-start mt-3">
        <button
          onClick={handleUseGpsLocation}
          className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all duration-200 shadow-md
                      ${gpsLoading ? 'bg-gray-300 text-gray-700 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'}
                      focus:outline-none focus:ring-2 focus:ring-blue-300`}
          disabled={gpsLoading}
        >
          {gpsLoading ? (
            <>
              <i className="fas fa-spinner fa-spin"></i> Fetching Location...
            </>
          ) : (
            <>
              <i className="fas fa-location-crosshairs"></i> Use My Location
            </>
          )}
        </button>
        {gpsError && <p className="ml-3 text-red-600 text-xs italic">{gpsError}</p>}
      </div>
    </div>
  );
}

export default LocationSearchInput;
