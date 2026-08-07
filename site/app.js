"use strict";

document.documentElement.classList.add("js");

const installTabs = Array.from(document.querySelectorAll("[data-install-tab]"));
const installPanels = Array.from(document.querySelectorAll("[role='tabpanel']"));
const copyStatus = document.querySelector(".copy-status");

function selectInstallTab(nextTab, moveFocus = true) {
  installTabs.forEach((tab) => {
    const selected = tab === nextTab;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });

  installPanels.forEach((panel) => {
    panel.hidden = panel.id !== nextTab.getAttribute("aria-controls");
  });

  if (moveFocus) nextTab.focus();
}

installTabs.forEach((tab, index) => {
  tab.addEventListener("click", () => selectInstallTab(tab, false));
  tab.addEventListener("keydown", (event) => {
    let nextIndex = null;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % installTabs.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + installTabs.length) % installTabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = installTabs.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    selectInstallTab(installTabs[nextIndex]);
  });
});

installPanels.forEach((panel, index) => {
  panel.hidden = index !== 0;
});

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Copy command was rejected");
}

document.querySelectorAll("[data-copy]").forEach((button) => {
  const defaultLabel = button.textContent;
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    try {
      await copyText(source.textContent);
      button.textContent = "Copied";
      button.dataset.state = "success";
      copyStatus.textContent = "Command copied to the clipboard.";
    } catch {
      button.textContent = "Copy failed";
      button.dataset.state = "error";
      copyStatus.textContent = "Copy failed. Select the command and copy it manually.";
    }

    window.setTimeout(() => {
      button.textContent = defaultLabel;
      delete button.dataset.state;
      copyStatus.textContent = "";
    }, 2200);
  });
});

const canvas = document.getElementById("particle-field");
const storySteps = Array.from(document.querySelectorAll("[data-particle-stage]"));
const particleStep = document.getElementById("particle-step");
const particleLabel = document.getElementById("particle-label");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function initializeParticleField() {
  if (!canvas || !canvas.getContext) return;
  const context = canvas.getContext("2d", { alpha: true });
  const labels = ["Inspect", "Plan", "Grant", "Invoke", "Evidence"];
  const particles = [];
  let width = 0;
  let height = 0;
  let stage = 0;
  let frame = 0;
  let running = true;
  let visible = true;

  function seeded(index, salt) {
    const value = Math.sin(index * 91.733 + salt * 17.171) * 43758.5453;
    return value - Math.floor(value);
  }

  function shapePoint(index, count, nextStage) {
    const t = count > 1 ? index / (count - 1) : 0;
    const jitterX = (seeded(index, nextStage + 1) - 0.5) * 0.055;
    const jitterY = (seeded(index, nextStage + 9) - 0.5) * 0.055;

    if (nextStage === 0) {
      const angle = index * 2.399963;
      const radius = 0.1 + 0.29 * Math.sqrt(t);
      return [0.5 + Math.cos(angle) * radius * 1.2 + jitterX, 0.47 + Math.sin(angle) * radius + jitterY];
    }

    if (nextStage === 1) {
      const lane = index % 4;
      const position = Math.floor(index / 4) / Math.max(1, Math.ceil(count / 4) - 1);
      return [0.14 + position * 0.72 + jitterX * 0.45, 0.28 + lane * 0.145 + jitterY * 0.35];
    }

    if (nextStage === 2) {
      const side = index % 2 === 0 ? -1 : 1;
      const angle = -1.38 + t * 2.76;
      return [0.5 + side * (0.1 + Math.cos(angle) * 0.27) + jitterX * 0.35, 0.5 + Math.sin(angle) * 0.34 + jitterY * 0.35];
    }

    if (nextStage === 3) {
      const beforeGate = t < 0.56;
      const local = beforeGate ? t / 0.56 : (t - 0.56) / 0.44;
      const spread = beforeGate ? (1 - local) * 0.24 : local * 0.18;
      return [0.08 + t * 0.84 + jitterX * spread, 0.5 + jitterY + (seeded(index, 31) - 0.5) * spread];
    }

    const columns = Math.ceil(Math.sqrt(count * 1.35));
    const rows = Math.ceil(count / columns);
    const column = index % columns;
    const row = Math.floor(index / columns);
    return [0.18 + (column / Math.max(1, columns - 1)) * 0.64 + jitterX * 0.25, 0.22 + (row / Math.max(1, rows - 1)) * 0.56 + jitterY * 0.25];
  }

  function setTargets(nextStage) {
    stage = nextStage;
    particleStep.textContent = String(nextStage + 1).padStart(2, "0");
    particleLabel.textContent = labels[nextStage];
    particles.forEach((particle, index) => {
      const [targetX, targetY] = shapePoint(index, particles.length, nextStage);
      particle.tx = targetX * width;
      particle.ty = targetY * height;
      if (reduceMotion.matches) {
        particle.x = particle.tx;
        particle.y = particle.ty;
      }
    });
  }

  function resizeCanvas() {
    const bounds = canvas.getBoundingClientRect();
    const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = Math.max(1, bounds.width);
    height = Math.max(1, bounds.height);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);

    const desiredCount = width < 520 ? 68 : 104;
    while (particles.length < desiredCount) {
      const index = particles.length;
      particles.push({
        x: seeded(index, 3) * width,
        y: seeded(index, 7) * height,
        tx: 0,
        ty: 0,
        size: 1.35 + seeded(index, 11) * 2.15,
      });
    }
    particles.length = desiredCount;
    setTargets(stage);
    draw();
  }

  function draw() {
    context.clearRect(0, 0, width, height);

    context.lineWidth = 0.75;
    context.strokeStyle = "rgba(83, 68, 59, 0.13)";
    for (let first = 0; first < particles.length; first += 1) {
      for (let second = first + 1; second < particles.length; second += 1) {
        const dx = particles[first].x - particles[second].x;
        const dy = particles[first].y - particles[second].y;
        if (dx * dx + dy * dy > 1200) continue;
        context.beginPath();
        context.moveTo(particles[first].x, particles[first].y);
        context.lineTo(particles[second].x, particles[second].y);
        context.stroke();
      }
    }

    particles.forEach((particle, index) => {
      const copper = index % 11 === 0 || (stage === 3 && Math.abs(particle.x - width * 0.55) < width * 0.07);
      context.fillStyle = copper ? "#a9452e" : "#24221f";
      context.beginPath();
      context.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
      context.fill();
    });
  }

  function animate() {
    if (!running) return;
    if (visible && !document.hidden) {
      if (!reduceMotion.matches) {
        particles.forEach((particle) => {
          particle.x += (particle.tx - particle.x) * 0.075;
          particle.y += (particle.ty - particle.y) * 0.075;
        });
      }
      draw();
    }
    frame = window.requestAnimationFrame(animate);
  }

  const stepObserver = new IntersectionObserver(
    (entries) => {
      const active = entries
        .filter((entry) => entry.isIntersecting)
        .sort((first, second) => second.intersectionRatio - first.intersectionRatio)[0];
      if (!active) return;
      const nextStage = Number(active.target.dataset.particleStage);
      storySteps.forEach((step) => step.classList.toggle("is-active", step === active.target));
      if (nextStage !== stage) setTargets(nextStage);
    },
    { rootMargin: "-20% 0px -20% 0px", threshold: [0.25, 0.5, 0.75] },
  );

  storySteps.forEach((step) => stepObserver.observe(step));

  const canvasObserver = new IntersectionObserver((entries) => {
    visible = entries[0].isIntersecting;
  });
  canvasObserver.observe(canvas);

  const resizeObserver = new ResizeObserver(resizeCanvas);
  resizeObserver.observe(canvas);
  reduceMotion.addEventListener("change", () => setTargets(stage));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !frame) animate();
  });

  resizeCanvas();
  animate();

  window.addEventListener("pagehide", () => {
    running = false;
    window.cancelAnimationFrame(frame);
    frame = 0;
  });
}

if (canvas) {
  const particleStarter = new IntersectionObserver(
    (entries, observer) => {
      if (!entries[0].isIntersecting) return;
      observer.disconnect();
      initializeParticleField();
    },
    { rootMargin: "600px 0px" },
  );
  particleStarter.observe(canvas);
}
