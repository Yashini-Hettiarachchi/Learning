// DOM Elements
const navToggle = document.querySelector('.nav-toggle');
const navMenu = document.querySelector('.nav-menu');
const sections = document.querySelectorAll('.section');
const navLinks = document.querySelectorAll('.nav-link');
const documentCards = document.querySelectorAll('.document-card');

// Navigation Toggle
navToggle.addEventListener('click', () => {
    navToggle.classList.toggle('active');
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking outside
document.addEventListener('click', (e) => {
    if (!navToggle.contains(e.target) && !navMenu.contains(e.target)) {
        navToggle.classList.remove('active');
        navMenu.classList.remove('active');
    }
});

// Smooth scrolling for navigation links
navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href');
        const targetSection = document.querySelector(targetId);
        
        // Close mobile menu if open
        navToggle.classList.remove('active');
        navMenu.classList.remove('active');
        
        // Scroll to section
        targetSection.scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Active navigation link based on scroll position
window.addEventListener('scroll', () => {
    let current = '';
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        
        if (window.scrollY >= (sectionTop - sectionHeight / 3)) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href').slice(1) === current) {
            link.classList.add('active');
        }
    });
});

// Document Preview Handling
documentCards.forEach(card => {
    const previewBtn = card.querySelector('.preview-btn');
    const downloadBtn = card.querySelector('.download-btn');
    const previewContainer = card.querySelector('.document-preview');
    const pdfViewer = card.querySelector('.pdf-viewer');
    const pdfPlaceholder = card.querySelector('.pdf-placeholder');
    const previewMessage = card.querySelector('.preview-message');
    const downloadPreviewBtn = card.querySelector('.download-preview-btn');
    
    if (previewBtn) {
        previewBtn.addEventListener('click', () => {
            const fileUrl = previewBtn.dataset.pdf;
            const isPdf = fileUrl.toLowerCase().endsWith('.pdf');
            
            if (isPdf) {
                // Handle PDF preview
                pdfPlaceholder.style.display = 'none';
                pdfViewer.style.display = 'block';
                pdfViewer.src = fileUrl;
                
                // Update button state
                previewBtn.textContent = 'Close Preview';
                previewBtn.classList.toggle('active');
                
                // Toggle preview visibility
                if (previewBtn.classList.contains('active')) {
                    previewContainer.style.height = '600px';
                } else {
                    previewContainer.style.height = '400px';
                    pdfViewer.src = '';
                    pdfPlaceholder.style.display = 'flex';
                    previewBtn.textContent = 'Preview Document';
                }
            } else {
                // Handle non-PDF files (like PowerPoint)
                pdfPlaceholder.style.display = 'none';
                if (previewMessage) {
                    previewMessage.style.display = 'flex';
                    previewMessage.style.flexDirection = 'column';
                    previewMessage.style.alignItems = 'center';
                    previewMessage.style.justifyContent = 'center';
                    previewMessage.style.gap = '1rem';
                }
                
                // Update button state
                previewBtn.textContent = 'Close Preview';
                previewBtn.classList.toggle('active');
                
                // Toggle preview visibility
                if (!previewBtn.classList.contains('active')) {
                    previewContainer.style.height = '400px';
                    pdfPlaceholder.style.display = 'flex';
                    if (previewMessage) {
                        previewMessage.style.display = 'none';
                    }
                    previewBtn.textContent = 'Preview Document';
                }
            }
        });
    }
    
    // Handle download preview button for non-PDF files
    if (downloadPreviewBtn) {
        downloadPreviewBtn.addEventListener('click', () => {
            const fileUrl = previewBtn.dataset.pdf;
            const link = document.createElement('a');
            link.href = fileUrl;
            link.download = fileUrl.split('/').pop();
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }
    
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            const downloadUrl = downloadBtn.dataset.pdf;
            
            // Create a temporary link element
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = downloadUrl.split('/').pop();
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }
});

// Intersection Observer for fade-in animations
const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.1
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe all sections and document cards
sections.forEach(section => observer.observe(section));
documentCards.forEach(card => observer.observe(card));

// Handle PDF viewer loading states
document.querySelectorAll('.pdf-viewer').forEach(viewer => {
    viewer.addEventListener('load', () => {
        viewer.classList.add('loaded');
    });
    
    viewer.addEventListener('error', () => {
        const placeholder = viewer.parentElement.querySelector('.pdf-placeholder');
        placeholder.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <p>Failed to load PDF preview</p>
            </div>
        `;
        placeholder.style.display = 'flex';
        viewer.style.display = 'none';
    });
});
// Add loading indicator for PDF previews
function showLoadingIndicator(container) {
    const loader = document.createElement('div');
    loader.className = 'pdf-loader';
    loader.innerHTML = `
        <div class="spinner"></div>
        <p>Loading preview...</p>
    `;
    container.appendChild(loader);
}

function removeLoadingIndicator(container) {
    const loader = container.querySelector('.pdf-loader');
    if (loader) {
        loader.remove();
    }
}

// Initialize loading indicators
documentCards.forEach(card => {
    const previewContainer = card.querySelector('.document-preview');
    const pdfViewer = card.querySelector('.pdf-viewer');
    
    if (pdfViewer) {
        pdfViewer.addEventListener('loadstart', () => {
            showLoadingIndicator(previewContainer);
        });
        
        pdfViewer.addEventListener('load', () => {
            removeLoadingIndicator(previewContainer);
        });
    }
}); 