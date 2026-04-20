export function ExpectedFlowCard() {
  return (
    <div className="card border border-base-300 bg-base-100 shadow-xl">
      <div className="card-body">
        <h2 className="card-title text-xl">Expected Flow</h2>
        <ul className="steps steps-vertical mt-2">
          <li className="step step-primary">Choose a mounted repository or provide an allowed path.</li>
          <li className="step step-primary">Choose heuristic-only or LLM-assisted judging.</li>
          <li className="step">Launch the scan and move to Activity for detailed runtime logs.</li>
          <li className="step">Open Report after completion for verdicts and suggestions.</li>
        </ul>
      </div>
    </div>
  );
}
