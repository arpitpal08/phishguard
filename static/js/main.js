// PhishGuard - Main JavaScript file

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Add event listener for URL input validation
    const urlInput = document.querySelector('input[name="url"]');
    if (urlInput) {
        urlInput.addEventListener('input', function() {
            validateURL(this);
        });
    }

    // Handle form submission with validation
    const urlForm = document.querySelector('form[action="/"]');
    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            const urlInput = this.querySelector('input[name="url"]');
            if (!validateURL(urlInput)) {
                e.preventDefault();
                return false;
            }
        });
    }

    // Copy URL to clipboard functionality
    const copyButtons = document.querySelectorAll('.copy-url-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const url = this.getAttribute('data-url');
            navigator.clipboard.writeText(url).then(() => {
                // Change button text temporarily
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            });
        });
    });

    // Dark mode toggle
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        });

        // Check for saved dark mode preference
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
    }
});

// URL validation function
function validateURL(input) {
    const urlPattern = /^(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;
    
    if (!input.value) {
        showValidationMessage(input, 'Please enter a URL');
        return false;
    }
    
    if (!urlPattern.test(input.value)) {
        showValidationMessage(input, 'Please enter a valid URL');
        return false;
    }
    
    clearValidationMessage(input);
    return true;
}

// Show validation error message
function showValidationMessage(input, message) {
    // Clear any existing message
    clearValidationMessage(input);
    
    // Create error message element
    const errorDiv = document.createElement('div');
    errorDiv.className = 'invalid-feedback d-block';
    errorDiv.textContent = message;
    
    // Add error class to input
    input.classList.add('is-invalid');
    
    // Insert error message after input
    input.parentNode.insertBefore(errorDiv, input.nextSibling);
}

// Clear validation error message
function clearValidationMessage(input) {
    input.classList.remove('is-invalid');
    
    // Remove any existing error message
    const existingError = input.nextElementSibling;
    if (existingError && existingError.className.includes('invalid-feedback')) {
        existingError.remove();
    }
}

// API call function for URL checking (for potential API integrations)
function checkURL(url, callback) {
    fetch('/api/check', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
    })
    .then(response => response.json())
    .then(data => {
        callback(null, data);
    })
    .catch(error => {
        callback(error, null);
    });
}

// Function to format probability as percentage
function formatProbability(probability) {
    return (probability * 100).toFixed(1) + '%';
} 