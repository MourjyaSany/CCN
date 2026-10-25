import { Component, type ReactNode } from "react";
import { Button, Card, EmptyState } from "@/components/ui";
import { AlertTriangle } from "lucide-react";

export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Card>
        <EmptyState
          icon={<AlertTriangle />}
          title="This view hit an error"
          hint={<span className="font-mono">{this.state.error.message}</span>}
          action={<Button onClick={() => this.setState({ error: null })}>Try again</Button>}
        />
      </Card>
    );
  }
}
