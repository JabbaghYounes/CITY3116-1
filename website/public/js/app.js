/**
 * VulnShop - Frontend JavaScript
 * Note: This code also contains some intentional vulnerabilities
 */

// Check if user is logged in
function checkAuth() {
    const user = localStorage.getItem('user');
    if (user) {
        try {
            const userData = JSON.parse(user);
            updateNavUser(userData);
        } catch (e) {
            console.error('Invalid user data in localStorage');
        }
    }
}

// Update navigation with user info
function updateNavUser(user) {
    const navUser = document.getElementById('navUser');
    if (navUser && user) {
        navUser.innerHTML = `
            <span>Welcome, ${user.username}</span>
            <a href="#" onclick="logout()">Logout</a>
        `;
    }
}

// Logout function
function logout() {
    localStorage.removeItem('user');
    document.cookie = 'user_data=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    window.location.href = '/login.html';
}

// A08: Intentionally vulnerable - reading unsigned cookie
function getUserFromCookie() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'user_data') {
            try {
                // A08: No integrity verification!
                return JSON.parse(decodeURIComponent(value));
            } catch (e) {
                return null;
            }
        }
    }
    return null;
}

// A02: Debug function exposed in production
window.debug = {
    showConfig: async function() {
        const response = await fetch('/api/debug');
        const data = await response.json();
        console.log('Server Config:', data);
        return data;
    },
    showUser: function() {
        console.log('LocalStorage User:', localStorage.getItem('user'));
        console.log('Cookie User:', getUserFromCookie());
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();

    // Log page access (but not to server - A09!)
    console.log(`Page accessed: ${window.location.pathname}`);
});

// A08: Vulnerable innerHTML usage (XSS potential)
function displayMessage(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (element) {
        // Vulnerable to XSS if message contains HTML
        element.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
    }
}

// Helper function for API calls
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Export functions for use in HTML
window.VulnShop = {
    checkAuth,
    logout,
    getUserFromCookie,
    displayMessage,
    apiCall
};
