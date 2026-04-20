export function ErrorBanner({ errorBanner }) {
  if (!errorBanner?.text) {
    return null;
  }

  return (
    <div role="alert" className="alert alert-error shadow-lg">
      <span className="font-semibold">{errorBanner.text}</span>
      {errorBanner.hint ? <span className="text-sm opacity-80">{errorBanner.hint}</span> : null}
    </div>
  );
}
