import { useRef, useMemo, useCallback, useState, useEffect } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import * as THREE from 'three';
import { forceSimulation, forceLink, forceManyBody, forceCenter } from 'd3-force-3d';
import useStore from '../stores/useStore';

// =============================================================================
// Cloudscape 6.0: ADVANCED FORCE-DIRECTED PHYSICS ENGINE
// =============================================================================

const MAX_VISIBLE_NODES = 400; // Controlled for extreme physics layout

const DUMMY = new THREE.Object3D();
const COLOR = new THREE.Color();

// Risk/provider → color mapping
function getNodeColor(node) {
  if (node.riskScore > 80) return '#ff1053'; // Neon Red
  if (node.riskScore > 50) return '#ff9900'; // AWS Orange
  if (node.provider === 'aws' || node.provider === 'AWS') return '#f5d547';
  if (node.provider === 'azure' || node.provider === 'AZURE') return '#00a1ff';
  return '#1e90ff';
}

// ---------------------------------------------------------------------------
// Particle Flow engine
// ---------------------------------------------------------------------------
function ParticleFlow({ links, nodesObj }) {
  const meshRef = useRef();
  
  // Create 2 particles per link for continuous flow
  const particles = useMemo(() => {
    return links.map(link => ({
      link,
      progress: Math.random(),
      speed: 0.002 + Math.random() * 0.003
    }));
  }, [links]);

  useFrame(() => {
    if (!meshRef.current) return;
    particles.forEach((p, i) => {
      p.progress += p.speed;
      if (p.progress > 1) p.progress = 0;

      const sourceNode = p.link.source;
      const targetNode = p.link.target;
      
      if (!sourceNode || !targetNode || sourceNode.x === undefined) return;

      const x = sourceNode.x + (targetNode.x - sourceNode.x) * p.progress;
      const y = sourceNode.y + (targetNode.y - sourceNode.y) * p.progress;
      const z = sourceNode.z + (targetNode.z - sourceNode.z) * p.progress;

      DUMMY.position.set(x, y, z);
      DUMMY.scale.set(0.4, 0.4, 0.4);
      DUMMY.updateMatrix();
      meshRef.current.setMatrixAt(i, DUMMY.matrix);
      
      // Pulse color based on threat
      const glowStr = (Math.sin(p.progress * Math.PI * 10) + 1) / 2;
      COLOR.set(p.link.source.riskScore > 50 ? '#ff1053' : '#00d2ff').multiplyScalar(0.5 + glowStr);
      meshRef.current.setColorAt(i, COLOR);
    });
    meshRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[null, null, particles.length]}>
      <sphereGeometry args={[1, 8, 8]} />
      <meshBasicMaterial transparent opacity={0.8} toneMapped={false} />
    </instancedMesh>
  );
}

// ---------------------------------------------------------------------------
// InstancedNodes & Edges
// ---------------------------------------------------------------------------
function PhysicsGraph({ nodes, edges, onSelect }) {
  const meshRef = useRef();
  const glowRef = useRef();
  const linesRef = useRef();
  
  // Setup d3-force-3d simulation
  const { simNodes, simLinks } = useMemo(() => {
    const nodeObj = {};
    const simNodes = nodes.map(n => {
      const clone = { ...n };
      nodeObj[n.id] = clone;
      return clone;
    });
    
    const simLinks = edges
      .filter(e => nodeObj[e.source] && nodeObj[e.target])
      .map(e => ({
        source: nodeObj[e.source],
        target: nodeObj[e.target],
        value: 1
      }));

    const simulation = forceSimulation(simNodes, 3)
      .force('link', forceLink(simLinks).id(d => d.id).distance(20))
      .force('charge', forceManyBody().strength(-80))
      .force('center', forceCenter());

    // Run simulation synchronously to stabilize initial layout
    for (let i = 0; i < 150; i++) simulation.tick();
    
    return { simNodes, simLinks, nodeObj };
  }, [nodes, edges]);

  useFrame(({ clock }) => {
    if (!meshRef.current || !glowRef.current || !linesRef.current) return;
    const time = clock.getElapsedTime();

    // 1. Update Nodes
    simNodes.forEach((node, i) => {
      // Gentle floating animation
      const floatY = Math.sin(time * 2 + i) * 0.5;
      DUMMY.position.set(node.x, node.y + floatY, node.z);
      
      // Pulse critical nodes
      let scale = 1;
      if (node.riskScore > 80) {
        scale = 1 + Math.sin(time * 5 + i) * 0.2;
      }
      DUMMY.scale.set(scale, scale, scale);
      DUMMY.updateMatrix();

      meshRef.current.setMatrixAt(i, DUMMY.matrix);
      glowRef.current.setMatrixAt(i, DUMMY.matrix);

      COLOR.set(getNodeColor(node));
      meshRef.current.setColorAt(i, COLOR);
      glowRef.current.setColorAt(i, COLOR);
    });

    meshRef.current.instanceMatrix.needsUpdate = true;
    glowRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
    if (glowRef.current.instanceColor) glowRef.current.instanceColor.needsUpdate = true;

    // 2. Update Edges
    const positions = linesRef.current.geometry.attributes.position.array;
    simLinks.forEach((link, i) => {
      const src = link.source;
      const tgt = link.target;
      const srcFloatY = Math.sin(time * 2 + simNodes.indexOf(src)) * 0.5;
      const tgtFloatY = Math.sin(time * 2 + simNodes.indexOf(tgt)) * 0.5;
      
      positions[i * 6]     = src.x;
      positions[i * 6 + 1] = src.y + srcFloatY;
      positions[i * 6 + 2] = src.z;
      
      positions[i * 6 + 3] = tgt.x;
      positions[i * 6 + 4] = tgt.y + tgtFloatY;
      positions[i * 6 + 5] = tgt.z;
    });
    linesRef.current.geometry.attributes.position.needsUpdate = true;
  });

  const handleClick = useCallback((e) => {
    e.stopPropagation();
    const idx = e.instanceId;
    if (idx !== undefined && simNodes[idx]) {
      onSelect(nodes.find(n => n.id === simNodes[idx].id)); // return original node object
    }
  }, [simNodes, nodes, onSelect]);

  const edgeGeometry = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(new Float32Array(simLinks.length * 6), 3));
    return geo;
  }, [simLinks]);

  return (
    <group>
      {/* Edges */}
      <lineSegments ref={linesRef} geometry={edgeGeometry}>
        <lineBasicMaterial color="#00a1ff" transparent opacity={0.15} blending={THREE.AdditiveBlending} />
      </lineSegments>

      {/* Nodes */}
      <instancedMesh ref={meshRef} args={[null, null, simNodes.length]} onClick={handleClick}>
        <sphereGeometry args={[1.2, 16, 16]} />
        <meshStandardMaterial roughness={0.2} metalness={0.8} />
      </instancedMesh>

      {/* Glowing Halos */}
      <instancedMesh ref={glowRef} args={[null, null, simNodes.length]}>
        <sphereGeometry args={[1.8, 12, 12]} />
        <meshBasicMaterial transparent opacity={0.2} blending={THREE.AdditiveBlending} depthWrite={false} />
      </instancedMesh>

      {/* Dynamic Data Flow Particles */}
      <ParticleFlow links={simLinks} />
    </group>
  );
}

// ---------------------------------------------------------------------------
// Scene Setup
// ---------------------------------------------------------------------------
function Scene({ nodes, edges }) {
  const { setSelectedNode } = useStore();

  const visibleNodes = useMemo(() => {
    if (nodes.length <= MAX_VISIBLE_NODES) return nodes;
    const highRisk = nodes.filter(n => n.riskScore > 50);
    const rest = nodes.filter(n => n.riskScore <= 50).sort(() => Math.random() - 0.5);
    return [...highRisk.slice(0, MAX_VISIBLE_NODES), ...rest.slice(0, Math.max(0, MAX_VISIBLE_NODES - highRisk.length))].slice(0, MAX_VISIBLE_NODES);
  }, [nodes]);

  const visibleIdSet = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => edges.filter(e => visibleIdSet.has(e.source) && visibleIdSet.has(e.target)), [edges, visibleIdSet]);

  return (
    <>
      <ambientLight intensity={0.2} />
      <pointLight position={[50, 50, 50]} intensity={2} color="#ffffff" distance={200} />
      <pointLight position={[-50, -50, -50]} intensity={1.5} color="#00d2ff" distance={200} />
      <pointLight position={[0, -20, 0]} intensity={2} color="#ff1053" distance={100} />
      
      <PhysicsGraph nodes={visibleNodes} edges={visibleEdges} onSelect={setSelectedNode} />
      
      <OrbitControls enableDamping dampingFactor={0.03} minDistance={10} maxDistance={150} autoRotate autoRotateSpeed={0.5} />
    </>
  );
}

// ---------------------------------------------------------------------------
// Graph3D Export
// ---------------------------------------------------------------------------
export default function Graph3D({ nodes, edges }) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  if (!nodes || nodes.length === 0) return <div style={{ color: '#8899aa', padding: 40, textAlign: 'center' }}>Loading Cloudscape Matrix...</div>;
  if (!ready) return <div style={{ color: '#8899aa', padding: 40, textAlign: 'center' }}>Initializing N-Body Physics Simulation...</div>;

  return (
    <Canvas
      camera={{ position: [0, 30, 80], fov: 50 }}
      gl={{ antialias: true, powerPreference: 'high-performance', alpha: true }}
      dpr={[1, 2]}
    >
      <Scene nodes={nodes} edges={edges} />
    </Canvas>
  );
}
