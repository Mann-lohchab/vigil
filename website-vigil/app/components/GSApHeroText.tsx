// // import { useEffect, useRef } from "react";
// // import { gsap } from "gsap";

// // interface GSApHeroTextProps {
// //   text: string;
// //   className?: string;
// // }

// // export function GSApHeroText({ text, className = "" }: GSApHeroTextProps) {
// //   const containerRef = useRef<HTMLDivElement>(null);
// //   const textRef = useRef<HTMLSpanElement>(null);

// //   useEffect(() => {
// //     const ctx = gsap.context(() => {

// //       const words = text.split(" ");

// //       if (textRef.current) {
// //         textRef.current.innerHTML = words
// //           .map(
// //             (word) => `
// //           <span class="word-mask">
// //             <span class="word">${word}</span>
// //           </span>
// //         `
// //           )
// //           .join(" ");
// //       }

// //       const wordEls = gsap.utils.toArray<HTMLElement>(".word");

// //       // initial state
// //       gsap.set(wordEls, {
// //         yPercent: 120,
// //       });

// //       // animation (similar to gsap.com hero)
// //       gsap.to(wordEls, {
// //         yPercent: 0,
// //         duration: 1.2,
// //         stagger: 0.07,
// //         ease: "power4.out",
// //       });

// //     }, containerRef);

// //     return () => ctx.revert();
// //   }, [text]);

// //   return (
// //     <div
// //       ref={containerRef}
// //       className={`hero-text-container ${className}`}
// //       style={{
// //         display: "inline-block",
// //       }}
// //     >
// //       <span ref={textRef} className="hero-text" />

// //       <style>{`
// //         .word-mask {
// //           overflow: hidden;
// //           display: inline-block;
// //         }

// //         .word {
// //           display: inline-block;
// //           will-change: transform;
// //         }

// //         .hero-text {
// //           font-weight: 700;
// //           line-height: 1.1;
// //         }
// //       `}</style>
// //     </div>
// //   );
// // }

// import { useRef, useEffect } from "react";
// import gsap from "gsap";

// export function GSApHeroText({ text }) {
//   const textRef = useRef([]);

//   useEffect(() => {
//     gsap.from(textRef.current, {
//       y: 120,
//       opacity: 0,
//       rotateX: -90,
//       transformOrigin: "top center",
//       ease: "power4.out",
//       duration: 1.2,
//       stagger: 0.08,
//       delay: 0.3
//     });
//   }, []);

//   return (
//     <span style={{ display: "inline-block" }}>
//       {text.split("").map((char, i) => (
//         <span
//           key={i}
//           ref={(el) => (textRef.current[i] = el)}
//           style={{
//             display: "inline-block",
//             willChange: "transform",
//           }}
//         >
//           {char}
//         </span>
//       ))}
//     </span>
//   );
// }