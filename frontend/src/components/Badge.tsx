import React from 'react';

type BadgeProps = {
    children: React.ReactNode;
    variant?: 'success' | 'protected' | 'primary' | 'rose';
    className?: string;
};

export default function Badge({ children, variant = 'primary', className = '' }: BadgeProps) {
    const cls = `badge badge--${variant} ${className}`;
    return <span className={cls}>{children}</span>;
}
