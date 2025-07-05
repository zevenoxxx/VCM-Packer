// Function to check if an element is in the viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Function to handle scroll animations
function handleScrollAnimation() {
    // Select all main content sections on index.html
    const sections = document.querySelectorAll('main section'); 

    sections.forEach(section => {
        if (isInViewport(section)) {
            section.classList.add('fade-in'); // Add 'fade-in' class if section is in viewport
        }
    });

    // Handle sections on download.html (if applicable and visible)
    // We can also target specific elements on download.html for animation if needed.
    // For now, the existing main section selector should cover it.
    const downloadPageSection = document.getElementById('downloads-page');
    if (downloadPageSection && isInViewport(downloadPageSection)) {
        downloadPageSection.classList.add('fade-in');
    }

    // You can add more specific selectors for animation on download.html like version cards
    // Example:
    const versionCards = document.querySelectorAll('.version-card');
    versionCards.forEach(card => {
        if (isInViewport(card)) {
            card.classList.add('fade-in'); // You might need a separate 'fade-in' class for cards or re-use based on desired effect
        }
    });

    // Note: If you want to use the same 'fade-in' class for sections and cards
    // you might need to adjust the CSS transition properties for .version-card
    // or create a new animation class like 'fade-in-card' for more control.
}

// Initial check when the page loads
document.addEventListener('DOMContentLoaded', handleScrollAnimation);

// Add event listener for scroll
window.addEventListener('scroll', handleScrollAnimation);
