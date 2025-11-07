import { Outlet } from 'react-router-dom';

export function Wrapper() {
    return (
        <>
            <div className="flex flex-col lg:flex-row grow py-(--page-space)">
                <div className="flex grow rounded-xl">
                    <div className="grow lg:overflow-hidden lg:ms-(--sidebar-width) lg:transition-[margin] lg:duration-300 lg:me-[calc(var(--aside-width))]">
                        <main className="grow px-2.5 lg:p-0" role="content">
                            <Outlet />
                        </main>
                    </div>
                </div>
            </div>
        </>
    );
}
