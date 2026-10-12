const canvas = document.querySelector("#cohort-scene");
const dataNode = document.querySelector("#cohort-data");
const statusNode = document.querySelector("#cohort-status");
const tooltip = document.querySelector("#cohort-tooltip");
const stage = canvas?.parentElement;

async function initializeCohort() {
  if (!canvas || !dataNode || !statusNode || !stage) return;

  let THREE;
  let OrbitControls;
  try {
    [THREE, { OrbitControls }] = await Promise.all([
      import("three"),
      import("three/addons/controls/OrbitControls.js"),
    ]);
  } catch {
    statusNode.textContent = "3D view unavailable in this browser. The student explanations remain available below.";
    canvas.hidden = true;
    return;
  }

  const students = JSON.parse(dataNode.textContent || "[]");
  const scene = new THREE.Scene();
  scene.background = new THREE.Color("#eaf0ec");
  const camera = new THREE.PerspectiveCamera(43, 1, 0.1, 100);
  camera.position.set(8, 7, 12);

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  } catch {
    statusNode.textContent = "3D view unavailable in this browser. The student explanations remain available below.";
    canvas.hidden = true;
  }

  if (renderer) {
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor("#eaf0ec", 1);
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.enablePan = false;
    controls.minDistance = 8;
    controls.maxDistance = 24;
    controls.autoRotate = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    controls.autoRotateSpeed = 0.28;
    controls.target.set(0, 0, 0);

    scene.add(new THREE.HemisphereLight("#ffffff", "#748b7f", 2.1));
    const keyLight = new THREE.DirectionalLight("#ffffff", 2.2);
    keyLight.position.set(5, 9, 7);
    scene.add(keyLight);

    const cohort = new THREE.Group();
    scene.add(cohort);
    const grid = new THREE.GridHelper(10, 10, "#93a79c", "#d0dbd4");
    grid.position.set(0, -5, 0);
    scene.add(grid);

    function addLine(start, end, color, opacity = 1) {
      const geometry = new THREE.BufferGeometry().setFromPoints([start, end]);
      const material = new THREE.LineBasicMaterial({ color, transparent: opacity < 1, opacity });
      scene.add(new THREE.Line(geometry, material));
    }

    for (let score = -3; score <= 5; score += 2) {
      addLine(new THREE.Vector3(score, -5, -5), new THREE.Vector3(score, 5, -5), "#c3d0c8", 0.55);
      addLine(new THREE.Vector3(-5, score, -5), new THREE.Vector3(5, score, -5), "#c3d0c8", 0.55);
    }
    addLine(new THREE.Vector3(-5, -5, -5), new THREE.Vector3(5, -5, -5), "#315e51");
    addLine(new THREE.Vector3(-5, -5, -5), new THREE.Vector3(-5, 5, -5), "#315e51");
    addLine(new THREE.Vector3(-5, -5, -5), new THREE.Vector3(-5, -5, 5), "#315e51");

    const sphereGeometry = new THREE.SphereGeometry(0.13, 18, 14);
    const pointMaterials = {
      Low: new THREE.MeshStandardMaterial({ color: "#27856f", roughness: 0.34, metalness: 0.12 }),
      Moderate: new THREE.MeshStandardMaterial({ color: "#ca852f", roughness: 0.34, metalness: 0.12 }),
      High: new THREE.MeshStandardMaterial({ color: "#b94f45", roughness: 0.34, metalness: 0.12 }),
      unknown: new THREE.MeshStandardMaterial({ color: "#788780", roughness: 0.4, metalness: 0.08 }),
    };
    const points = [];
    const toWorld = (value) => Math.max(-5, Math.min(5, Number(value ?? 50) / 10 - 5));

    students.forEach((student) => {
      const riskKnown = student.risk !== null && student.risk !== undefined;
      const marker = new THREE.Mesh(sphereGeometry, pointMaterials[riskKnown ? student.risk_band : "unknown"]);
      marker.position.set(toWorld(student.success), toWorld(student.readiness), toWorld(riskKnown ? student.risk : 50));
      marker.userData.student = student;
      marker.castShadow = true;
      cohort.add(marker);
      points.push(marker);
    });

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    let hovered = null;

    function getHit(event) {
      const bounds = canvas.getBoundingClientRect();
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1;
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      return raycaster.intersectObjects(points, false)[0]?.object || null;
    }

    canvas.addEventListener("pointermove", (event) => {
      const hit = getHit(event);
      canvas.style.cursor = hit ? "pointer" : "grab";
      if (hit === hovered || !tooltip) return;
      hovered = hit;
      if (!hit) {
        tooltip.hidden = true;
        return;
      }
      const student = hit.userData.student;
      tooltip.textContent = `${student.name}\nSuccess ${student.success ?? "Not scored"}  ·  Readiness ${student.readiness}  ·  Risk ${student.risk ?? "Not scored"}`;
      const bounds = stage.getBoundingClientRect();
      tooltip.style.left = `${Math.min(event.clientX - bounds.left + 14, bounds.width - 250)}px`;
      tooltip.style.top = `${Math.max(12, event.clientY - bounds.top - 20)}px`;
      tooltip.hidden = false;
    });

    canvas.addEventListener("pointerleave", () => {
      hovered = null;
      if (tooltip) tooltip.hidden = true;
    });

    canvas.addEventListener("click", (event) => {
      const hit = getHit(event);
      const studentId = hit?.userData.student.id;
      if (studentId !== undefined) {
        const row = document.querySelector(`[data-student-id="${studentId}"]`);
        const details = row?.querySelector("details");
        if (details) details.open = true;
        row?.scrollIntoView({ behavior: "smooth", block: "center" });
        row?.focus({ preventScroll: true });
      }
    });

    function resize() {
      const width = Math.max(1, stage.clientWidth);
      const height = Math.max(300, Math.min(440, Math.round(width * 0.43)));
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    }

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(stage);
    resize();
    statusNode.textContent = students.length ? `${students.length} students mapped` : "No students are available in this cohort.";

    function animate() {
      controls.update();
      renderer.render(scene, camera);
      requestAnimationFrame(animate);
    }
    animate();
  }
}

initializeCohort();
