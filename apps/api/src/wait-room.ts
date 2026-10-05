export type WaitRoomOptions = {
  enabled: boolean;
  maxActive: number;
  maxQueue: number;
  timeoutSeconds: number;
};

export type Admission = {
  allowed: boolean;
  queued: boolean;
  retryAfter?: number;
  reason?: string;
  release: () => void;
};

type Entry = { id: number; enqueuedAt: number; resolve: (value: Admission) => void; timer: ReturnType<typeof setTimeout> };

export class WaitRoom {
  private active = 0;
  private nextId = 1;
  private queue: Entry[] = [];

  constructor(private readonly options: WaitRoomOptions) {}

  enter(): Admission | Promise<Admission> {
    if (!this.options.enabled || this.active < this.options.maxActive) return this.grant();
    if (this.queue.length >= this.options.maxQueue) return this.reject("等候室已满");
    return new Promise<Admission>((resolve) => {
      const entry = { id: this.nextId++, enqueuedAt: Date.now(), resolve, timer: undefined as unknown as ReturnType<typeof setTimeout> };
      this.queue.push(entry);
      const timer = setTimeout(() => {
        const current = this.queue.find((item) => item.id === entry.id);
        if (!current) return;
        const actualIndex = this.queue.indexOf(current);
        if (actualIndex >= 0) this.queue.splice(actualIndex, 1);
        resolve(this.reject("等候室等待超时", Math.ceil(this.options.timeoutSeconds)));
      }, this.options.timeoutSeconds * 1000);
      timer.unref?.();
      entry.timer = timer;
    });
  }

  snapshot(): { active: number; queued: number } { return { active: this.active, queued: this.queue.length }; }

  private grant(): Admission {
    this.active += 1;
    let released = false;
    return { allowed: true, queued: false, release: () => {
      if (released) return;
      released = true;
      this.active = Math.max(0, this.active - 1);
      this.drain();
    } };
  }

  private reject(reason: string, retryAfter = 1): Admission {
    return { allowed: false, queued: false, retryAfter, reason, release: () => undefined };
  }

  private drain(): void {
    while (this.active < this.options.maxActive && this.queue.length) {
      const entry = this.queue.shift()!;
      clearTimeout(entry.timer);
      entry.resolve(this.grant());
    }
  }
}
