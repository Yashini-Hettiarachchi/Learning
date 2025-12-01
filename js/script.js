document.addEventListener('DOMContentLoaded', () => {
    // Navigation Elements
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    const navLinks = document.querySelectorAll('.nav-link');
    const searchForm = document.querySelector('.search-form');
    const searchInput = document.querySelector('.search-input');

    // Toggle Mobile Menu
    navToggle.addEventListener('click', () => {
        const isExpanded = navToggle.getAttribute('aria-expanded') === 'true';
        navToggle.setAttribute('aria-expanded', !isExpanded);
        navToggle.classList.toggle('active');
        navMenu.classList.toggle('active');
    });

    // Keyboard Support for Nav Toggle
    navToggle.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            navToggle.click();
        }
    });

    // Close Mobile Menu on Link Click
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (navMenu.classList.contains('active')) {
                navToggle.classList.remove('active');
                navMenu.classList.remove('active');
                navToggle.setAttribute('aria-expanded', 'false');
            }
        });
    });

    // Smooth Scrolling for Anchor Links
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80,
                    behavior: 'smooth'
                });
            }
            // Update active link
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });

    // Search Functionality
    if (searchForm) {
        searchForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const searchTerm = searchInput.value.trim().toLowerCase();
            if (!searchTerm) {
                alert('Please enter a search term.');
                return;
            }
            const sections = document.querySelectorAll('section[id]');
            let found = false;
            sections.forEach(section => {
                const sectionText = section.textContent.toLowerCase();
                if (sectionText.includes(searchTerm)) {
                    found = true;
                    window.scrollTo({
                        top: section.offsetTop - 80,
                        behavior: 'smooth'
                    });
                    section.classList.add('highlight');
                    setTimeout(() => section.classList.remove('highlight'), 2000);
                }
            });
            if (!found) {
                alert(`No results found for: "${searchTerm}"`);
            }
        });
    }

    // Document Preview
    const previewButtons = document.querySelectorAll('.preview-btn');
    previewButtons.forEach(button => {
        button.addEventListener('click', () => {
            const pdfPath = button.getAttribute('data-pdf');
            const viewer = button.closest('.document-card').querySelector('.pdf-viewer');
            const placeholder = button.closest('.document-card').querySelector('.pdf-placeholder');
            if (pdfPath.endsWith('.pdf')) {
                placeholder.style.display = 'none';
                viewer.style.display = 'block';
                viewer.src = pdfPath;
            } else {
                placeholder.style.display = 'flex';
                viewer.style.display = 'none';
            }
        });
    });

    // Intersection Observer for Section Animations
    const sections = document.querySelectorAll('.section');
    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fadeIn');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    sections.forEach(section => observer.observe(section));

    // Highlight Animation CSS
    const style = document.createElement('style');
    style.textContent = `
        .highlight {
            background-color: #fefcbf;
            transition: background-color 0.3s ease;
        }
        .fadeIn {
            animation: fadeIn 0.5s ease-in-out;
            opacity: 1;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    document.head.appendChild(style);
});