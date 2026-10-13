import React from 'react';

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: 'primary' | 'ghost';
    asLink?: boolean;
};

export default function Button({ variant = 'primary', children, className = '', ...props }: ButtonProps) {
    const base = `btn ${variant === 'primary' ? 'btn-primary' : 'btn-ghost'} ${className}`;
    return (
        <button className={base} {...props}>
            {children}
        </button>
    );
}
