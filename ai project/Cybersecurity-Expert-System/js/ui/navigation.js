/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Navigation Controller: Multi-Section Routing, Mobile Toggle, Scroll Spy
 */

class NavigationController {
  constructor() {
    this.navLinks = document.querySelectorAll("[data-nav-target]");
    this.sections = document.querySelectorAll(".app-section");
    this.mobileToggle = document.getElementById("mobileNavToggle");
    this.navMenu = document.getElementById("primaryNavMenu");
    this.currentSection = "home";

    this.init();
  }

  init() {
    // Click listeners on navigation links
    this.navLinks.forEach(link => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const targetSection = link.getAttribute("data-nav-target");
        this.navigateTo(targetSection);
      });
    });

    // Mobile menu toggle
    if (this.mobileToggle && this.navMenu) {
      this.mobileToggle.addEventListener("click", () => {
        this.navMenu.classList.toggle("nav-open");
        const isOpen = this.navMenu.classList.contains("nav-open");
        this.mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });
    }

    // Hash change routing
    window.addEventListener("hashchange", () => {
      const hash = window.location.hash.replace("#", "");
      if (hash && document.getElementById(hash)) {
        this.navigateTo(hash, false);
      }
    });

    // Initial load route
    const initialHash = window.location.hash.replace("#", "");
    if (initialHash && document.getElementById(initialHash)) {
      this.navigateTo(initialHash, false);
    } else {
      this.navigateTo("home", false);
    }
  }

  navigateTo(sectionId, updateHash = true) {
    const targetElement = document.getElementById(sectionId);
    if (!targetElement) return;

    // Update active section visibility
    this.sections.forEach(sec => {
      if (sec.id === sectionId) {
        sec.classList.add("active-section");
        sec.removeAttribute("hidden");
      } else {
        sec.classList.remove("active-section");
        sec.setAttribute("hidden", "true");
      }
    });

    // Update nav active link states
    this.navLinks.forEach(link => {
      if (link.getAttribute("data-nav-target") === sectionId) {
        link.classList.add("active-link");
      } else {
        link.classList.remove("active-link");
      }
    });

    // Close mobile menu if open
    if (this.navMenu && this.navMenu.classList.contains("nav-open")) {
      this.navMenu.classList.remove("nav-open");
    }

    this.currentSection = sectionId;

    if (updateHash) {
      window.location.hash = sectionId;
    }

    // Scroll to top of window smoothly
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { NavigationController };
}
