import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ Button */
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "bg-accent text-white hover:bg-accent/90 shadow-sm",
        secondary: "bg-raised text-fg border border-border hover:bg-border/40",
        ghost: "text-muted hover:text-fg hover:bg-border/40",
        danger: "bg-bad text-white hover:bg-bad/90",
        good: "bg-good text-white hover:bg-good/90",
      },
      size: { sm: "h-8 px-3", md: "h-9 px-4", icon: "h-9 w-9", xs: "h-7 px-2 text-xs" },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
  },
);
Button.displayName = "Button";

/* -------------------------------------------------------------------- Card */
export const Card = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("rounded-lg border border-border bg-surface shadow-card", className)} {...p} />
);

export const CardHeader = ({ title, subtitle, actions, className }: {
  title: React.ReactNode; subtitle?: React.ReactNode; actions?: React.ReactNode; className?: string;
}) => (
  <div className={cn("flex items-start justify-between gap-3 border-b border-border px-4 py-3", className)}>
    <div className="min-w-0">
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
    </div>
    {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
  </div>
);

export const CardBody = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("p-4", className)} {...p} />
);

/* ------------------------------------------------------------------- Badge */
const badgeVariants = cva("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold", {
  variants: {
    tone: {
      neutral: "bg-border/60 text-muted",
      good: "bg-good/15 text-good",
      warn: "bg-warn/15 text-warn",
      bad: "bg-bad/15 text-bad",
      info: "bg-info/15 text-info",
      accent: "bg-accent/15 text-accent",
    },
  },
  defaultVariants: { tone: "neutral" },
});

export const Badge = ({ tone, className, ...p }: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) => (
  <span className={cn(badgeVariants({ tone }), className)} {...p} />
);

export const SeverityBadge = ({ p }: { p: number }) => {
  const tone = p >= 0.95 ? "bad" : p >= 0.85 ? "bad" : p >= 0.6 ? "warn" : "neutral";
  const text = p >= 0.95 ? "Critical" : p >= 0.85 ? "High" : p >= 0.6 ? "Medium" : "Low";
  return <Badge tone={tone}>{text}</Badge>;
};

export const StatusDot = ({ tone = "good", pulse }: { tone?: "good" | "warn" | "bad" | "neutral"; pulse?: boolean }) => (
  <span
    className={cn(
      "inline-block size-2 rounded-full",
      { good: "bg-good", warn: "bg-warn", bad: "bg-bad", neutral: "bg-subtle" }[tone],
      pulse && "animate-pulseDot",
    )}
  />
);

/* ---------------------------------------------------------------- Skeleton */
export const Skeleton = ({ className }: { className?: string }) => (
  <div className={cn("relative overflow-hidden rounded-md bg-border/50", className)}>
    <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/10 to-transparent" />
  </div>
);

/* ------------------------------------------------------------- Empty state */
export const EmptyState = ({ icon, title, hint, action }: {
  icon?: React.ReactNode; title: string; hint?: React.ReactNode; action?: React.ReactNode;
}) => (
  <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
    {icon && <div className="mb-1 text-subtle [&_svg]:size-8">{icon}</div>}
    <p className="text-sm font-medium text-fg">{title}</p>
    {hint && <p className="max-w-md text-xs text-muted">{hint}</p>}
    {action && <div className="mt-2">{action}</div>}
  </div>
);

/* ------------------------------------------------------------------ Inputs */
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...p }, ref) => (
    <input
      ref={ref}
      className={cn("h-9 w-full rounded-md border border-border bg-surface px-3 text-sm text-fg placeholder:text-subtle focus:border-accent focus:outline-none", className)}
      {...p}
    />
  ),
);
Input.displayName = "Input";

export const Select = ({ className, children, ...p }: React.SelectHTMLAttributes<HTMLSelectElement>) => (
  <select
    className={cn("h-9 rounded-md border border-border bg-surface px-2.5 text-sm text-fg focus:border-accent focus:outline-none", className)}
    {...p}
  >
    {children}
  </select>
);

export const Field = ({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) => (
  <label className="flex flex-col gap-1.5">
    <span className="label">{label}</span>
    {children}
    {hint && <span className="text-[11px] text-subtle">{hint}</span>}
  </label>
);

export const Switch = ({ checked, onCheckedChange, label }: { checked: boolean; onCheckedChange: (v: boolean) => void; label?: string }) => (
  <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg">
    <SwitchPrimitive.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      className="relative h-5 w-9 rounded-full bg-border transition-colors data-[state=checked]:bg-accent"
    >
      <SwitchPrimitive.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-[18px]" />
    </SwitchPrimitive.Root>
    {label}
  </label>
);

export const Segmented = <T extends string>({ value, onChange, options }: {
  value: T; onChange: (v: T) => void; options: Array<{ value: T; label: string }>;
}) => (
  <div className="inline-flex rounded-md border border-border bg-raised p-0.5" role="radiogroup">
    {options.map((o) => (
      <button
        key={o.value}
        role="radio"
        aria-checked={value === o.value}
        onClick={() => onChange(o.value)}
        className={cn(
          "rounded-[5px] px-2.5 py-1 text-xs font-medium transition-colors",
          value === o.value ? "bg-surface text-fg shadow-sm" : "text-muted hover:text-fg",
        )}
      >
        {o.label}
      </button>
    ))}
  </div>
);

/* -------------------------------------------------------------------- Tabs */
export const Tabs = TabsPrimitive.Root;
export const TabsList = ({ className, ...p }: React.ComponentProps<typeof TabsPrimitive.List>) => (
  <TabsPrimitive.List className={cn("flex gap-1 border-b border-border", className)} {...p} />
);
export const TabsTrigger = ({ className, ...p }: React.ComponentProps<typeof TabsPrimitive.Trigger>) => (
  <TabsPrimitive.Trigger
    className={cn(
      "-mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted transition-colors hover:text-fg data-[state=active]:border-accent data-[state=active]:text-fg",
      className,
    )}
    {...p}
  />
);
export const TabsContent = ({ className, ...p }: React.ComponentProps<typeof TabsPrimitive.Content>) => (
  <TabsPrimitive.Content className={cn("pt-4 focus-visible:outline-none", className)} {...p} />
);

/* ----------------------------------------------------------------- Tooltip */
export const TooltipProvider = TooltipPrimitive.Provider;
export const Tip = ({ content, children }: { content: React.ReactNode; children: React.ReactNode }) => (
  <TooltipPrimitive.Root delayDuration={250}>
    <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        sideOffset={6}
        className="z-50 max-w-xs rounded-md border border-border bg-raised px-2.5 py-1.5 text-xs text-fg shadow-pop"
      >
        {content}
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  </TooltipPrimitive.Root>
);

/* -------------------------------------------------------- Drawer / Dialog */
export const Drawer = ({ open, onOpenChange, title, subtitle, children, width = "w-[min(560px,100vw)]" }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: React.ReactNode; subtitle?: React.ReactNode;
  children: React.ReactNode; width?: string;
}) => (
  <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/30 backdrop-blur-[1px]" />
      <DialogPrimitive.Content
        className={cn("fixed inset-y-0 right-0 z-50 flex flex-col border-l border-border bg-surface shadow-pop", width)}
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
          <div>
            <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
            {subtitle && <DialogPrimitive.Description className="mt-0.5 text-xs text-muted">{subtitle}</DialogPrimitive.Description>}
          </div>
          <DialogPrimitive.Close asChild>
            <Button variant="ghost" size="icon" aria-label="Close"><X /></Button>
          </DialogPrimitive.Close>
        </div>
        <div className="scroll-thin flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  </DialogPrimitive.Root>
);

export const Modal = ({ open, onOpenChange, title, children }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: React.ReactNode; children: React.ReactNode;
}) => (
  <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/40" />
      <DialogPrimitive.Content className="fixed left-1/2 top-[12vh] z-50 w-[min(640px,calc(100vw-32px))] -translate-x-1/2 rounded-lg border border-border bg-surface shadow-pop">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <DialogPrimitive.Title className="text-sm font-semibold">{title}</DialogPrimitive.Title>
          <DialogPrimitive.Close asChild>
            <Button variant="ghost" size="icon" aria-label="Close"><X /></Button>
          </DialogPrimitive.Close>
        </div>
        <div className="max-h-[70vh] overflow-y-auto p-5">{children}</div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  </DialogPrimitive.Root>
);

/* ------------------------------------------------------------- Data table */
export const DataTable = ({ className, ...p }: React.TableHTMLAttributes<HTMLTableElement>) => (
  <div className="scroll-thin overflow-x-auto">
    <table className={cn("w-full border-collapse text-sm [&_td]:border-b [&_td]:border-border [&_td]:px-3 [&_td]:py-2 [&_th]:border-b [&_th]:border-border [&_th]:bg-raised [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:text-[11px] [&_th]:font-semibold [&_th]:uppercase [&_th]:tracking-wider [&_th]:text-subtle [&_tr:hover_td]:bg-raised/60", className)} {...p} />
  </div>
);

/* ---------------------------------------------------------- Page header */
export const PageHeader = ({ title, subtitle, actions }: { title: string; subtitle?: React.ReactNode; actions?: React.ReactNode }) => (
  <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
    <div>
      <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
      {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
    </div>
    {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
