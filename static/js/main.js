/**
 * PhishGuard - Main JavaScript
 * Adds dynamic behaviors and interactivity to the phishing detection application
 */

document.addEventListener('DOMContentLoaded', function() {
    // Matrix text effect for cyber header
    setupMatrixEffect();
    
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltipTriggerList.length > 0) {
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    }
    
    // Add cyber glow effect to nav items on hover
    const navItems = document.querySelectorAll('.navbar-nav .nav-link');
    navItems.forEach(item => {
        item.addEventListener('mouseenter', () => {
            item.style.textShadow = '0 0 8px rgba(111, 255, 233, 0.8)';
        });
        item.addEventListener('mouseleave', () => {
            item.style.textShadow = 'none';
        });
    });
    
    // Animated counters for dashboard statistics
    animateCounters();
    
    // Apply pulsing effect to risk badges
    const highRiskBadges = document.querySelectorAll('.risk-badge-high');
    highRiskBadges.forEach(badge => {
        setInterval(() => {
            badge.classList.add('pulse-animation');
            setTimeout(() => {
                badge.classList.remove('pulse-animation');
            }, 1000);
        }, 3000);
    });
    
    // Highlight URL parts on hover in the report
    const urlParts = document.querySelectorAll('.url-part');
    urlParts.forEach(part => {
        part.addEventListener('mouseenter', function() {
            this.classList.add('url-part-highlight');
        });
        part.addEventListener('mouseleave', function() {
            this.classList.remove('url-part-highlight');
        });
    });
    
    // Interactive form validation
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.addEventListener('input', function() {
            validateURL(this);
        });
    }
    
    // Add cyber-themed cursor trail on certain pages
    if (document.querySelector('.cyber-header')) {
        setupCursorTrail();
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

/**
 * Validate URL input with visual feedback
 */
function validateURL(inputElement) {
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    
    if (urlPattern.test(inputElement.value)) {
        inputElement.classList.remove('is-invalid');
        inputElement.classList.add('is-valid');
    } else {
        inputElement.classList.remove('is-valid');
        if (inputElement.value.length > 0) {
            inputElement.classList.add('is-invalid');
        } else {
            inputElement.classList.remove('is-invalid');
        }
    }
}

/**
 * Animate numeric counters
 */
function animateCounters() {
    const counters = document.querySelectorAll('.counter');
    
    counters.forEach(counter => {
        const target = parseInt(counter.getAttribute('data-target'));
        const duration = 1500; // ms
        const step = Math.ceil(target / (duration / 30)); // Update every 30ms
        let current = 0;
        
        const updateCounter = () => {
            current += step;
            if (current > target) {
                current = target;
                clearInterval(timer);
            }
            counter.textContent = current;
        };
        
        const timer = setInterval(updateCounter, 30);
    });
}

/**
 * Setup matrix raining code effect
 */
function setupMatrixEffect() {
    const matrixElement = document.querySelector('.matrix-loading');
    if (!matrixElement) return;
    
    const text = matrixElement.textContent;
    matrixElement.textContent = '';
    
    for (let i = 0; i < text.length; i++) {
        const span = document.createElement('span');
        span.textContent = text[i];
        span.style.animationDelay = (i * 0.1) + 's';
        span.classList.add('matrix-char');
        matrixElement.appendChild(span);
    }
}

/**
 * Setup cyber-themed cursor trail effect
 */
function setupCursorTrail() {
    const trailContainer = document.createElement('div');
    trailContainer.className = 'cursor-trail-container';
    document.body.appendChild(trailContainer);
    
    let coords = { x: 0, y: 0 };
    
    document.addEventListener('mousemove', function(e) {
        coords.x = e.clientX;
        coords.y = e.clientY;
        
        const trail = document.createElement('div');
        trail.className = 'cursor-trail';
        trail.style.left = coords.x + 'px';
        trail.style.top = coords.y + 'px';
        
        trailContainer.appendChild(trail);
        
        setTimeout(() => {
            trail.remove();
        }, 800);
    });
}

// Add class to body when scrolled
window.addEventListener('scroll', function() {
    if (window.scrollY > 50) {
        document.body.classList.add('scrolled');
    } else {
        document.body.classList.remove('scrolled');
    }
});

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